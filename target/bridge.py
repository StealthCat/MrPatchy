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
    tmp = path.with_name(path.name+'.mrpatchy-new')
    fd = os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if tmp.exists(): tmp.unlink()
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
        atomic('/usr/local/lib/mrpatchy/agent.py',code,0o644)
        atomic('/etc/systemd/system/mrpatchy-agent.service',UNIT.encode(),0o644)
        run(['systemctl','daemon-reload']); run(['systemctl','enable','--now','mrpatchy-agent']); run(['systemctl','restart','mrpatchy-agent'])
        return {'deployed':req['sha256'],'unit_sha256':hashlib.sha256(UNIT.encode()).hexdigest()}
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
    with open(ROOT/'bridge.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        raw = sys.stdin.buffer.read(4_000_001)
        if len(raw)>4_000_000: raise ValueError('Request too large')
        print(json.dumps(handle(json.loads(raw))))
if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'error':str(e)})); sys.exit(1)
