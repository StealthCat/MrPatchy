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

import os
import selectors
import signal
import subprocess
import time

def bounded(args,timeout=900,env=None,limit=16_000_000):
    process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
    output=bytearray();errors=bytearray();selector=selectors.DefaultSelector()
    selector.register(process.stdout,selectors.EVENT_READ,output)
    selector.register(process.stderr,selectors.EVENT_READ,errors)
    deadline=time.monotonic()+timeout
    try:
        while selector.get_map():
            if time.monotonic()>deadline: raise TimeoutError('Operation timed out; verify target state before retrying')
            for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj);continue
                key.data.extend(chunk)
                if len(output)+len(errors)>limit: raise RuntimeError('Operation output exceeded 16 MB limit')
        process.wait(timeout=max(.1,deadline-time.monotonic()))
        if process.returncode: raise RuntimeError((output+errors)[-16000:].decode(errors='replace'))
        return output.decode(errors='replace'),errors.decode(errors='replace')
    finally:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait()
        selector.close();process.stdout.close();process.stderr.close()

def run(args, timeout=1800):
    out,err=bounded(args,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    return (out+err)[-20000:]
def repo_path(name):
    if name == '/etc/apt/sources.list': return Path(name)
    if not re.fullmatch(r'/etc/apt/sources\.list\.d/[A-Za-z0-9_.-]+\.(list|sources)',name): raise ValueError('Invalid source path')
    return Path(name)

def process_evidence(req):
    path=req.get('executable','');expected=req.get('sha256','')
    checks=req.get('checks',[])
    if not isinstance(path,str) or not path.startswith('/') or len(path)>4096 or not re.fullmatch('[a-f0-9]{64}',expected):
        raise ValueError('Invalid executable identity')
    if not isinstance(checks,list) or not set(checks)<={'package','service','executable'}: raise ValueError('Invalid evidence checks')
    result={'identity_verified':False,'checks':checks}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            if os.readlink(proc/'exe')!=path: continue
            # Open the process executable, not an arbitrary caller-provided file.
            with open(proc/'exe','rb') as stream:
                checksum=hashlib.sha256()
                for chunk in iter(lambda:stream.read(1024*1024),b''): checksum.update(chunk)
                digest=checksum.hexdigest()
                info=os.fstat(stream.fileno())
            if digest!=expected: continue
            result['identity_verified']=True
            if 'executable' in checks:
                result['executable']={'sha256':digest,'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode & 0o7777,'size':info.st_size,
                    'status':[line for line in (proc/'status').read_text().splitlines() if line.split(':')[0] in ('Uid','Gid','CapEff','NoNewPrivs','Seccomp')]}
            if 'package' in checks:
                try: result['package']=run(['dpkg-query','-S','--',path],timeout=15)[:8000]
                except RuntimeError: result['package']='No installed package ownership found'
            if 'service' in checks:
                groups=(proc/'cgroup').read_text()
                units=re.findall(r'(?:^|/)([A-Za-z0-9_.@:-]+\.service)(?:/|$)',groups,re.M)
                result['service']=[]
                for unit in sorted(set(units))[:3]:
                    result['service'].append(run(['systemctl','show',unit,'--property=Id,LoadState,ActiveState,SubState,FragmentPath,User,Group,NoNewPrivileges,ProtectSystem'],timeout=15)[:8000])
            return result
        except (FileNotFoundError,ProcessLookupError): continue
        except PermissionError:
            result['inaccessible_processes']=result.get('inaccessible_processes',0)+1
    result['reason']='No running executable matches the recorded path and SHA-256; process may have exited or changed'
    return result

def recovery_hook(operation,identifier):
    hook=Path('/etc/mrpatchy/rollback')
    info=hook.stat()
    if not hook.is_file() or hook.is_symlink() or info.st_uid!=0 or info.st_mode & 0o022 or not info.st_mode & 0o100:
        raise ValueError('Rollback adapter must be a root-owned, non-writable executable')
    if operation not in ('snapshot','rollback','probe') or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',identifier):raise ValueError('Invalid recovery operation')
    result=json.loads(run([str(hook),operation,identifier],timeout=1800))
    if not isinstance(result,dict):raise ValueError('Invalid rollback adapter response')
    return result

def protected_patch(req):
    policy=req.get('policy',{})
    job=req.get('job_id','')
    if not re.fullmatch(r'[a-f0-9-]{36}',job):raise ValueError('A durable job ID is required')
    directory=ROOT/'transactions';directory.mkdir(mode=0o700,exist_ok=True)
    journal=directory/(job+'.json')
    if journal.exists():
        state=json.loads(journal.read_text())
        if state.get('state')=='complete':return state['result']
        raise RuntimeError('Prior patch attempt is incomplete; reconcile target state before retrying')
    state={'state':'preparing','job':job,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    snapshot=None
    if policy.get('rollback'):
        probe=recovery_hook('probe',job)
        if probe.get('ready') is not True:raise ValueError('Rollback adapter is not ready')
        snapshot=recovery_hook('snapshot',job).get('snapshot')
        if not isinstance(snapshot,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',snapshot):raise ValueError('Invalid snapshot ID')
        state['snapshot']=snapshot
    atomic(journal,json.dumps(state).encode())
    try:
        result=handle({'action':'patch','packages':req['packages']})
        health=handle({'action':'health'})
        if health['failed_units'] or not health['collector_active']:raise RuntimeError('Post-patch health failed: '+json.dumps(health))
        result['health']=health
        state.update(state='complete',result=result)
        atomic(journal,json.dumps(state).encode())
        if policy.get('reboot') and health['reboot_required']:
            run(['systemd-run','--unit=mrpatchy-reboot-'+job,'--on-active=10s','/usr/bin/systemctl','reboot'],timeout=15)
            result['reboot_scheduled']=True;result['boot_before']=state['boot_id']
            state['result']=result;atomic(journal,json.dumps(state).encode())
        return result
    except Exception as error:
        state.update(state='failed',error=str(error)[:4000])
        atomic(journal,json.dumps(state).encode())
        if snapshot and policy.get('rollback'):
            recovery=recovery_hook('rollback',snapshot)
            state['rollback']=recovery;state['state']='rolled-back';atomic(journal,json.dumps(state).encode())
            if recovery.get('reboot_required'):
                if not policy.get('reboot'):raise RuntimeError('Rollback prepared; reboot required but policy forbids automatic reboot')
                run(['systemd-run','--unit=mrpatchy-rollback-'+job,'--on-active=10s','/usr/bin/systemctl','reboot'],timeout=15)
        raise RuntimeError('Patch failed; recovery state: '+json.dumps(state))

def handle(req):
    action = req.get('action')
    if action == 'evidence': return process_evidence(req)
    if action == 'operation-status':
        with open(ROOT/'bridge.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return {'busy':True}
            return {'busy':False}
    if action == 'observability':
        if type(req.get('ebpf')) is not bool:raise ValueError('Boolean eBPF setting required')
        atomic(ROOT/'observability.json',json.dumps({'ebpf':req['ebpf']}).encode())
        # BPF needs kernel access; the optional collector runs outside restrictive service sandbox.
        overrides=Path('/etc/systemd/system/mrpatchy-agent.service.d');overrides.mkdir(exist_ok=True)
        dropin=overrides/'observability.conf'
        if req['ebpf']:atomic(dropin,b'[Service]\nProtectSystem=false\nNoNewPrivileges=false\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n',0o644)
        else:dropin.unlink(missing_ok=True)
        run(['systemctl','daemon-reload']);run(['systemctl','restart','mrpatchy-agent'])
        return {'configured':True,'ebpf':req['ebpf']}
    if action == 'protected-patch':return protected_patch(req)
    if action == 'recovery-status':
        return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'rollback_adapter':Path('/etc/mrpatchy/rollback').is_file(),'systemd':Path('/run/systemd/system').exists()}
    if action == 'authorized-keys':
        keys=req.get('keys')
        if not isinstance(keys,list) or not 1<=len(keys)<=2:raise ValueError('One or two Ed25519 keys required')
        for key in keys:
            if not isinstance(key,str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+',key):raise ValueError('Invalid public key')
            blob=base64.b64decode(key.split()[1],validate=True)
            if len(blob)!=51 or blob[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('Invalid Ed25519 encoding')
        content=''.join('restrict,command="/usr/bin/sudo -n /usr/bin/python3 -I /usr/local/lib/mrpatchy/bridge.py" '+key+' mrpatchy\n' for key in keys)
        atomic(ROOT/'.ssh/authorized_keys',content.encode(),0o644)
        return {'authorized_keys_sha256':hashlib.sha256(content.encode()).hexdigest()}
    if action == 'health':
        failed=run(['systemctl','--failed','--no-legend','--plain'],timeout=15)
        return {'failed_units':failed.strip(),'reboot_required':Path('/var/run/reboot-required').exists(),
                'collector_active':run(['systemctl','is-active','mrpatchy-agent'],timeout=15).strip()=='active'}
    if action == 'verify':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import MANAGED,digest
        files={}
        optional='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'
        for path in MANAGED+([optional] if Path(optional).exists() else []):
            info=Path(path).stat()
            files[path]={'sha256':digest(path),'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode & 0o7777}
        return {'files':files,'active':run(['systemctl','is-active','mrpatchy-agent'],timeout=15).strip()=='active'}
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
        for k in ['inventory','telemetry','collector-error','ebpf-status','ebpf-diagnostic']:
            p = ROOT/(k+'.json')
            if p.exists(): result[k] = json.loads(p.read_text())
        if (ROOT/'events.db').exists():
            sys.path.insert(0,'/usr/local/lib/mrpatchy')
            from agent import pending_events
            result.update(pending_events())
        return result
    if action == 'ack':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import acknowledge
        return acknowledge(req.get('ids'))
    if action == 'inventory':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import inventory
        return inventory()
    if action == 'repository':
        p = repo_path(req['path']); content = req['content'].encode()
        if p.is_symlink(): raise ValueError('Refusing symlink source file')
        if len(content)>1_000_000: raise ValueError('Source too large')
        backups = ROOT/'backups'; backups.mkdir(mode=0o700,exist_ok=True)
        if p.exists(): atomic(backups/(str(time.time_ns())+'.json'),json.dumps({'path':str(p),'content':p.read_text()}).encode())
        atomic(p,content,0o644)
        return {'saved':str(p),'backup_directory':str(backups)}
    if action == 'backups':
        backups=ROOT/'backups'
        rows=[]
        for p in sorted(backups.glob('*.json'),reverse=True)[:100]:
            item=json.loads(p.read_text())
            rows.append({'id':p.stem,'path':item['path'],'content':item['content']})
        return {'backups':rows}
    if action == 'repair':
        # Explicit operator action; potentially runs maintainer scripts.
        return {'output':run(['apt-get','-y','--no-remove','--fix-broken','-o','Dpkg::Options::=--force-confold','install'])+run(['dpkg','--force-confold','--configure','-a'])}
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
    if request.get('action') in ('snapshot','ack','evidence','backups','operation-status'):
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
