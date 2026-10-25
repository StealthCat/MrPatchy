#!/usr/bin/python3
"""Fixed sudo/SSH entry point. JSON protocol, no arbitrary shell command."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tempfile

ROOT = Path('/opt/drpatch')
UNIT = '''[Unit]
Description=Mr Patchy telemetry collector
After=network.target
[Service]
ExecStart=/usr/bin/python3 -I /usr/local/lib/mrpatchy/agent.py
Restart=always
RestartSec=5
User=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/drpatch
ProtectHome=read-only
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
[Install]
WantedBy=multi-user.target
'''
def atomic(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink(): raise ValueError('Refusing symlink destination')
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            # os.open's mode is filtered by the bridge's 077 umask.
            # Public signing keys and source files must remain readable by APT.
            os.fchmod(f.fileno(), mode)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)

def run(args, timeout=1800):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    if result.returncode: raise RuntimeError((result.stdout+result.stderr)[-20000:])
    return (result.stdout+result.stderr)[-20000:]
def repo_path(name):
    if name == '/etc/apt/sources.list': return Path(name)
    if not re.fullmatch(r'/etc/apt/sources\.list\.d/[A-Za-z0-9_.-]+\.(list|sources)',name): raise ValueError('Invalid source path')
    return Path(name)
def handle(req):
    action = req.get('action')
    if action == 'deploy':
        code = base64.b64decode(req['agent'],validate=True)
        if len(code)>1_000_000 or hashlib.sha256(code).hexdigest()!=req['sha256']: raise ValueError('Invalid agent digest')
        compile(code, 'agent.py', 'exec')
        bridge = None
        if 'bridge' in req:
            bridge = base64.b64decode(req['bridge'],validate=True)
            if len(bridge)>1_000_000 or hashlib.sha256(bridge).hexdigest()!=req.get('bridge_sha256'):
                raise ValueError('Invalid bridge digest')
            compile(bridge,'bridge.py','exec')
        unit = req.get('unit',UNIT).encode()
        if len(unit)>100_000 or ('unit' in req and hashlib.sha256(unit).hexdigest()!=req.get('unit_sha256')):
            raise ValueError('Invalid systemd unit digest')
        # Validate the complete deployment before replacing any managed file.
        if bridge is not None: atomic('/usr/local/lib/mrpatchy/bridge.py',bridge,0o644)
        atomic('/usr/local/lib/mrpatchy/agent.py',code,0o644)
        atomic('/etc/systemd/system/mrpatchy-agent.service',unit,0o644)
        run(['systemctl','daemon-reload']); run(['systemctl','enable','--now','mrpatchy-agent']); run(['systemctl','restart','mrpatchy-agent'])
        return {'deployed':req['sha256'],'unit_sha256':hashlib.sha256(unit).hexdigest(),'bridge_sha256':hashlib.sha256(Path('/usr/local/lib/mrpatchy/bridge.py').read_bytes()).hexdigest()}
    if action == 'snapshot':
        result = {}
        for k in ['inventory','telemetry','collector-error']:
            p = ROOT/(k+'.json')
            if p.exists(): result[k] = json.loads(p.read_text())
        return result
    if action == 'inventory':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import inventory
        return inventory()
    if action == 'repository':
        p = repo_path(req['path']); content = req['content'].encode()
        if len(content)>1_000_000: raise ValueError('Source too large')
        backups = ROOT/'backups'; backups.mkdir(mode=0o700,exist_ok=True)
        if p.exists(): atomic(backups/(str(time.time_ns())+'-'+p.name),p.read_bytes())
        atomic(p,content,0o644)
        return {'saved':str(p),'backup_directory':str(backups)}
    if action == 'key':
        name = req['name']
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.(gpg|asc)',name): raise ValueError('Invalid key filename')
        data = base64.b64decode(req['data'],validate=True)
        if len(data)>2_000_000: raise ValueError('Key too large')
        Path('/etc/apt/keyrings').mkdir(exist_ok=True,mode=0o755)
        atomic('/etc/apt/keyrings/'+name,data,0o644)
        return {'saved':'/etc/apt/keyrings/'+name}
    if action == 'patch':
        packages = req.get('packages',[])
        if not packages or len(packages)>500 or any(not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+(?::[a-z0-9-]+)?=[A-Za-z0-9.+:~\-]+',x) for x in packages): raise ValueError('Explicit package=version list required')
        # Only operator-requested installation uses APT on the target.
        out = run(['apt-get','-o','APT::Update::Error-Mode=any','update'])
        out += run(['apt-get','-y','--no-remove','--only-upgrade','-o','Dpkg::Options::=--force-confold','install','--',*packages])
        return {'output':out}
    raise ValueError('Unsupported action')
def main():
    os.umask(0o077)
    raw = sys.stdin.buffer.read(4_000_001)
    if len(raw)>4_000_000: raise ValueError('Request too large')
    request = json.loads(raw)
    if not isinstance(request, dict): raise ValueError('Request must be a JSON object')
    if request.get('action') == 'snapshot':
        # The collector writes snapshots atomically. Reading them must never
        # wait behind a long APT installation holding the mutation lock.
        print(json.dumps(handle(request)))
        return
    with open(ROOT/'bridge.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        print(json.dumps(handle(request)))

if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'error':str(e)})); sys.exit(1)
