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
import stat
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
        directory_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory_fd)
        finally:os.close(directory_fd)
    finally:
        tmp.unlink(missing_ok=True)

import os
import selectors
import signal
import subprocess
import time

def bounded(args,timeout=900,env=None,limit=16_000_000,allowed_codes=(0,),return_status=False,pass_fds=(),memory_limit=None):
    import resource
    def limits():resource.setrlimit(resource.RLIMIT_AS,(memory_limit,memory_limit))
    process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True,pass_fds=pass_fds,preexec_fn=limits if memory_limit is not None else None)
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
        if process.returncode not in allowed_codes: raise RuntimeError((output+errors)[-16000:].decode(errors='replace'))
        result=(output.decode(errors='replace'),errors.decode(errors='replace'))
        return (*result,process.returncode) if return_status else result
    except BaseException:
        # A parent may exit while its descendants keep the pipes/work alive.
        # Kill the original process group on failure even if poll() has reaped it.
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        raise
    finally:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait()
        selector.close();process.stdout.close();process.stderr.close()

def run(args, timeout=1800):
    out,err=bounded(args,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive'})
    return (out+err)[-20000:]
def rpm_backend():
    return not Path('/var/lib/dpkg/status').exists()

def rpm_module():
    sys.path.insert(0,'/usr/local/lib/mrpatchy')
    try:import rpm_support
    except ImportError:from target import rpm_support
    return rpm_support

def repo_path(name):
    if rpm_backend():
        if not rpm_module().source_path(name):raise ValueError('Invalid RPM source path')
        return Path(name)
    if name == '/etc/apt/sources.list': return Path(name)
    if not re.fullmatch(r'/etc/apt/sources\.list\.d/[A-Za-z0-9_.-]+\.(list|sources)',name): raise ValueError('Invalid source path')
    return Path(name)

def process_evidence(req):
    path=req.get('executable','');expected=req.get('sha256','')
    checks=req.get('checks',[])
    if not isinstance(path,str) or not path.startswith('/') or len(path)>4096 or not re.fullmatch('[a-f0-9]{64}',expected):
        raise ValueError('Invalid executable identity')
    if not isinstance(checks,list) or not set(checks)<={'package','service','executable'}: raise ValueError('Invalid evidence checks')
    result={'identity_verified':False,'checks':checks};deadline=time.monotonic()+10
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            if os.readlink(proc/'exe')!=path: continue
            # Open the process executable, not an arbitrary caller-provided file.
            sys.path.insert(0,'/usr/local/lib/mrpatchy')
            from agent import hash_artifact
            metadata={}
            digest=hash_artifact(proc/'exe',{},deadline=deadline,metadata=metadata)
            if digest!=expected: continue
            result['identity_verified']=True
            if 'executable' in checks:
                result['executable']={'sha256':digest,**metadata,
                    'status':[line for line in (proc/'status').read_text().splitlines() if line.split(':')[0] in ('Uid','Gid','CapEff','NoNewPrivs','Seccomp')]}
            if 'package' in checks:
                try: result['package']=run((['rpm','-qf','--',path] if rpm_backend() else ['dpkg-query','-S','--',path]),timeout=15)[:8000]
                except RuntimeError: result['package']='No installed package ownership found'
            if 'service' in checks:
                groups=(proc/'cgroup').read_text()
                units=re.findall(r'(?:^|/)([A-Za-z0-9_.@:-]+\.service)(?:/|$)',groups,re.M)
                result['service']=[]
                for unit in sorted(set(units))[:3]:
                    result['service'].append(run(['systemctl','show',unit,'--property=Id,LoadState,ActiveState,SubState,FragmentPath,User,Group,NoNewPrivileges,ProtectSystem'],timeout=15)[:8000])
            return result
        except (FileNotFoundError,ProcessLookupError): continue
        except ValueError:
            result['unverified_processes']=result.get('unverified_processes',0)+1
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

def transaction_path(job):
    if not isinstance(job,str) or not re.fullmatch(r'[a-f0-9-]{36}',job):raise ValueError('A durable job ID is required')
    directory=ROOT/'transactions';directory.mkdir(mode=0o700,exist_ok=True)
    return directory/(job+'.json')


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def schedule_reboot(journal,state,rollback=False):
    # Persist intent before the side effect. If submission is interrupted or
    # ambiguous, the journal cannot be mistaken for a completed transaction.
    prefix='rollback_reboot' if rollback else 'reboot'
    state['state']=prefix+'_pending';state['boot_before']=boot_id()
    atomic(journal,json.dumps(state).encode())
    run(['systemd-run','--unit=mrpatchy-'+prefix.replace('_','-')+'-'+state['job'],
         '--on-active=10s','/usr/bin/systemctl','reboot'],timeout=15)
    state['state']=prefix+'_scheduled';atomic(journal,json.dumps(state).encode())
    return {**state.get('result',{}),'outcome':'rollback_pending' if rollback else 'reboot_pending',
            'reboot_scheduled':True,'boot_before':state['boot_before']}


PATCH_CONFIG_ROOT=Path('/etc')


def patch_evidence():
    """Content/metadata only: no configuration plaintext crosses the SSH boundary."""
    sys.path.insert(0,'/usr/local/lib/mrpatchy')
    try:
        from agent import hash_artifact,MANAGED
        from release import fingerprint,conffiles,service_inventory
    except ImportError:
        from target.agent import hash_artifact,MANAGED
        from target.release import fingerprint,conffiles,service_inventory
    inv=handle({'action':'inventory'})
    if rpm_backend():run(['rpm','--verifydb'],timeout=60)
    elif run(['dpkg','--audit'],timeout=60).strip():raise ValueError('Package state must be clean before recovery verification')
    services=service_inventory(run(['systemctl','list-units','--type=service','--state=running','--no-legend','--plain'],timeout=30))
    health=handle({'action':'health'})
    if health.get('failed_units') or not health.get('collector_active'):raise ValueError('Service health must be clean before recovery verification')
    names=(set() if rpm_backend() else set(conffiles(inv['status']))) | set(MANAGED)
    deadline=time.monotonic()+30
    def walk_error(error):raise error
    for directory,dirs,files in os.walk(PATCH_CONFIG_ROOT,followlinks=False,onerror=walk_error):
        names.update(str(Path(directory)/name) for name in dirs+files)
        if len(names)>10000 or time.monotonic()>deadline:raise ValueError('Configuration recovery manifest exceeds capture budget')
    configs={};cache={}
    for name in sorted(names):
        if time.monotonic()>deadline:raise ValueError('Configuration recovery manifest exceeds capture budget')
        path=Path(name)
        try:info=path.lstat()
        except FileNotFoundError:
            configs[name]={'missing':True};continue
        entry={'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid}
        if stat.S_ISLNK(info.st_mode):entry['link']=os.readlink(path)
        elif stat.S_ISREG(info.st_mode):entry['sha256']=hash_artifact(path,cache,expected=(info.st_dev,info.st_ino),deadline=deadline)
        elif not stat.S_ISDIR(info.st_mode):raise ValueError('Unsupported configuration file type: '+name)
        configs[name]=entry
    result={'version':1,'inventory_hash':fingerprint(inv),'configs':configs,'services':services}
    if len(json.dumps(result).encode())>3_000_000:raise ValueError('Configuration recovery manifest is too large')
    return result


def verify_patch_original(original):
    if not isinstance(original,dict) or original.get('version')!=1 or not original.get('configs'):
        raise ValueError('Original patch recovery evidence is missing; reconcile target state')
    current=patch_evidence()
    if any(current.get(key)!=original.get(key) for key in ('inventory_hash','configs')):
        raise ValueError('Original packages, repositories, trust or configurations were not restored')
    if not set(original.get('services',[]))<=set(current['services']):
        raise ValueError('Previously running services were not restored')
    return {'outcome':'rolled_back','original_state_verified':True,'boot_after':boot_id()}


def rollback_transaction(journal,state):
    if not state.get('snapshot') or not state['policy'].get('rollback'):
        raise RuntimeError('No approved snapshot rollback is available; reconcile target state')
    state['state']='rollback_pending';atomic(journal,json.dumps(state).encode())
    recovery=recovery_hook('rollback',state['snapshot'])
    state['rollback']=recovery;state['state']='rollback_prepared'
    state['result']={'outcome':'rollback_pending','patch_error':state.get('error','Post-reboot health failed'),'rollback':recovery}
    atomic(journal,json.dumps(state).encode())
    if recovery.get('reboot_required'):
        if not state['policy'].get('reboot'):
            raise RuntimeError('Rollback prepared; reboot required but policy forbids automatic reboot')
        return schedule_reboot(journal,state,rollback=True)
    health=handle({'action':'health'})
    if health['failed_units'] or not health['collector_active']:
        raise RuntimeError('Rollback health could not be verified; reconcile target state')
    verified=verify_patch_original(state.get('original'))
    state['state']='rolled_back';state['result'].update(**verified,health=health)
    atomic(journal,json.dumps(state).encode());return state['result']


def complete_recovery(req):
    journal=transaction_path(req.get('job_id'));state=json.loads(journal.read_text())
    if state['state'] in ('complete','rolled_back'):return state['result']
    if state['state'] not in ('reboot_pending','reboot_scheduled','rollback_reboot_pending','rollback_reboot_scheduled'):
        raise RuntimeError('Recovery has no recorded reboot intent')
    if boot_id()==state['boot_before']:raise RuntimeError('Target has not rebooted yet')
    health=handle({'action':'health'})
    if health['failed_units'] or not health['collector_active']:raise RuntimeError('Post-reboot health is not ready')
    rolled_back=state['state'].startswith('rollback_')
    if rolled_back:state['result'].update(verify_patch_original(state.get('original')))
    state['state']='rolled_back' if rolled_back else 'complete'
    state['result'].update(outcome=state['state'],reboot_verified=True,health=health)
    atomic(journal,json.dumps(state).encode());return state['result']


def rollback_after_reboot(req):
    journal=transaction_path(req.get('job_id'));state=json.loads(journal.read_text())
    if state['state']=='rolled_back':return state['result']
    if state['state'] not in ('reboot_pending','reboot_scheduled') or boot_id()==state['boot_before']:
        raise RuntimeError('Post-reboot rollback requires an observed reboot and an unrecovered patch transaction')
    state['error']='Post-reboot health did not recover within the central verification window'
    return rollback_transaction(journal,state)


def protected_patch(req):
    policy=req.get('policy',{});job=req.get('job_id','');journal=transaction_path(job)
    if journal.exists():
        state=json.loads(journal.read_text())
        if state.get('state')=='complete':return state['result']
        raise RuntimeError('Prior patch attempt is incomplete; reconcile target state before retrying')
    health_before=handle({'action':'health'})
    if (not isinstance(health_before,dict) or 'failed_units' not in health_before or health_before['failed_units'] not in ('',[]) or health_before.get('collector_active') is not True):
        raise ValueError('Pre-patch service health must be clean for automatic recovery; no package changes attempted')
    state={'state':'preparing','job':job,'policy':policy,'boot_before':boot_id(),'health_before':health_before}
    atomic(journal,json.dumps(state).encode())
    if policy.get('rollback'):
        original=req.get('original')
        verify_patch_original(original)
        state['original']=original
        atomic(journal,json.dumps(state).encode())
        probe=recovery_hook('probe',job)
        if probe.get('ready') is not True:raise ValueError('Rollback adapter is not ready')
        snapshot=recovery_hook('snapshot',job).get('snapshot')
        if not isinstance(snapshot,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',snapshot):raise ValueError('Invalid snapshot ID')
        state['snapshot']=snapshot
    state['state']='patching';atomic(journal,json.dumps(state).encode())
    try:
        result=handle({'action':'patch','packages':req['packages']})
        health=handle({'action':'health'})
        if health['failed_units'] or not health['collector_active']:raise RuntimeError('Post-patch health failed: '+json.dumps(health))
    except Exception as error:
        state.update(state='failed',error=str(error)[:4000]);atomic(journal,json.dumps(state).encode())
        if state.get('snapshot'):return rollback_transaction(journal,state)
        raise RuntimeError('Patch failed; recovery state: '+json.dumps(state)) from error
    state['result']={**result,'health':health}
    state['state']='patched';atomic(journal,json.dumps(state).encode())
    if policy.get('reboot') and health['reboot_required']:
        return schedule_reboot(journal,state)
    state['state']='complete';state['result']['outcome']='complete'
    atomic(journal,json.dumps(state).encode());return state['result']

AGENT_FILES=('/usr/local/lib/mrpatchy/rpm_support.py','/usr/local/lib/mrpatchy/release.py',
             '/usr/local/lib/mrpatchy/agent.py','/usr/local/lib/mrpatchy/bridge.py',
             '/etc/systemd/system/mrpatchy-agent.service','/etc/sudoers.d/mrpatchy',
             '/opt/drpatch/.ssh/authorized_keys')
AGENT_DROPIN='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'

def agent_file_status(path):
    """No imports from inspected helpers; reject symlinks and writable parents."""
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);file_fd=None
    try:
        parts=Path(path).parts[1:]
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
            info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode & 0o022:raise ValueError('Unsafe parent')
        file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        before=os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>1_000_000:raise ValueError('Invalid managed file')
        digest=hashlib.sha256();total=0
        while True:
            chunk=os.read(file_fd,65536)
            if not chunk:break
            total+=len(chunk)
            if total>1_000_000:raise ValueError('Managed file grew')
            digest.update(chunk)
        after=os.fstat(file_fd);named=os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (named.st_dev,named.st_ino)!=(before.st_dev,before.st_ino):raise ValueError('Managed file changed')
        return {'sha256':digest.hexdigest(),'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode)}
    except FileNotFoundError:return {'missing':True}
    except (OSError,ValueError):return {'unsafe':True}
    finally:
        if file_fd is not None:os.close(file_fd)
        os.close(fd)

def agent_status():
    files={path:agent_file_status(path) for path in (*AGENT_FILES,AGENT_DROPIN)}
    def systemctl(*args):
        out,err,code=bounded(['systemctl',*args,'mrpatchy-agent.service'],timeout=5,limit=32000,allowed_codes=(0,1,3,4),return_status=True)
        if err:raise ValueError('Service status diagnostics prevent verification')
        return out.strip(),code
    active,active_code=systemctl('is-active');enabled,enabled_code=systemctl('is-enabled')
    properties,code=systemctl('show','--property=FragmentPath','--property=DropInPaths')
    if code:raise ValueError('Service configuration unavailable')
    values=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
    return {'version':1,'files':files,'directories_secure':not any(row.get('unsafe') for row in files.values()),
            'active':active_code==0 and active=='active','enabled':enabled_code==0 and enabled=='enabled',
            'unit_path':values.get('FragmentPath'),'dropins':values.get('DropInPaths','').split()}

def handle(req):
    action = req.get('action')
    if isinstance(action,str) and action.startswith('release-'):
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        import release
        if action=='release-inspect':return release.inspection()
        if action=='release-configs':return release.configurations(req.get('paths'))
        if action=='release-status':return release.read_state(req.get('job_id'))
        if action=='release-start':return release.start(req)
        if action=='release-verify':return release.verify(req.get('job_id'))
        if action=='release-restored':return release.restored(req['plan'])
        if action=='release-rollback':return release.rollback(req.get('job_id'))
        raise ValueError('Unsupported release action')
    if action == 'vendor-inspect':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import vendor_inspect
        return vendor_inspect(req.get('manifest'))
    if action == 'security-inspect-custom':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import security_inspect
        return security_inspect(req.get('packages'),req.get('persistence',True),req.get('custom_paths'))
    if action == 'security-inspect':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import security_inspect
        return security_inspect(req.get('packages'),req.get('persistence',True))
    if action == 'yara-scan':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import security_scan
        return security_scan(req.get('paths'),req.get('rules'))
    if action == 'security-scan':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import security_scan
        return security_scan(req.get('paths'))
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
    if action == 'patch-inspect':return patch_evidence()
    if action == 'patch-restored':return verify_patch_original(req.get('original'))
    if action == 'protected-patch':return protected_patch(req)
    if action == 'complete-recovery':return complete_recovery(req)
    if action == 'rollback-patch':return rollback_after_reboot(req)
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
        # Health comparisons need the complete list, never run()'s trailing 20 KB.
        failed,diagnostics=bounded(['systemctl','--failed','--no-legend','--plain','--no-pager'],timeout=15,
                                   env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},limit=1_000_000)
        if diagnostics.strip():raise RuntimeError('Unable to obtain an unambiguous failed-unit health snapshot')
        return {'failed_units':failed.strip(),'reboot_required':Path('/var/run/reboot-required').exists() or (rpm_backend() and (ROOT/'rpm-reboot-required').is_file() and (ROOT/'rpm-reboot-required').read_text().strip()==boot_id()),
                'collector_active':run(['systemctl','is-active','mrpatchy-agent'],timeout=15).strip()=='active'}
    if action == 'agent-status':return agent_status()
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
        release_code=None
        if 'release' in req:
            release_code=base64.b64decode(req['release'],validate=True)
            if len(release_code)>1_000_000 or hashlib.sha256(release_code).hexdigest()!=req.get('release_sha256'):raise ValueError('Invalid release runner digest')
            compile(release_code,'release.py','exec')
        rpm_code=None
        if 'rpm_support' in req:
            rpm_code=base64.b64decode(req['rpm_support'],validate=True)
            if len(rpm_code)>1_000_000 or hashlib.sha256(rpm_code).hexdigest()!=req.get('rpm_sha256'):raise ValueError('Invalid RPM helper digest')
            compile(rpm_code,'rpm_support.py','exec')
        unit = req.get('unit',UNIT).encode()
        if len(unit)>100_000 or ('unit' in req and hashlib.sha256(unit).hexdigest()!=req.get('unit_sha256')):
            raise ValueError('Invalid systemd unit digest')
        # Validate the complete deployment before replacing any managed file.
        if rpm_code is not None:atomic('/usr/local/lib/mrpatchy/rpm_support.py',rpm_code,0o644)
        if release_code is not None:atomic('/usr/local/lib/mrpatchy/release.py',release_code,0o644)
        if bridge is not None: atomic('/usr/local/lib/mrpatchy/bridge.py',bridge,0o644)
        atomic('/usr/local/lib/mrpatchy/agent.py',code,0o644)
        atomic('/etc/systemd/system/mrpatchy-agent.service',unit,0o644)
        run(['systemctl','daemon-reload']); run(['systemctl','enable','--now','mrpatchy-agent']); run(['systemctl','restart','mrpatchy-agent'])
        return {**({'rpm_sha256':req['rpm_sha256']} if rpm_code is not None else {}),**({'release_sha256':req['release_sha256']} if release_code is not None else {}),'deployed':req['sha256'],'unit_sha256':hashlib.sha256(unit).hexdigest(),'bridge_sha256':hashlib.sha256(Path('/usr/local/lib/mrpatchy/bridge.py').read_bytes()).hexdigest()}
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
    if action == 'events':
        sys.path.insert(0,'/usr/local/lib/mrpatchy')
        from agent import pending_events
        return pending_events()
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
        if rpm_backend():rpm_module().repositories({str(p):req['content']},rpm_module().local_inventory()['rpm_vars'])
        atomic(p,content,0o644)
        if rpm_backend() and Path('/usr/sbin/restorecon').exists():run(['/usr/sbin/restorecon',str(p)])
        return {'saved':str(p),'backup_directory':str(backups)}
    if action == 'backups':
        backups=ROOT/'backups'
        rows=[]
        for p in sorted(backups.glob('*.json'),reverse=True)[:100]:
            item=json.loads(p.read_text())
            rows.append({'id':p.stem,'path':item['path'],'content':item['content']})
        return {'backups':rows}
    if action == 'repair':
        if rpm_backend():
            return {'output':run(['rpm','--rebuilddb'])+run(['rpm','--verifydb'])+'RPM database rebuilt and verified; dependency repair requires a reviewed patch transaction.'}
        # Explicit operator action; potentially runs maintainer scripts.
        return {'output':run(['apt-get','-y','--no-remove','--fix-broken','-o','Dpkg::Options::=--force-confold','install'])+run(['dpkg','--force-confold','--configure','-a'])}
    if action == 'key':
        name = req['name']
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.(gpg|asc)',name): raise ValueError('Invalid key filename')
        data = base64.b64decode(req['data'],validate=True)
        if len(data)>2_000_000: raise ValueError('Key too large')
        if rpm_backend():
            Path('/etc/pki/rpm-gpg').mkdir(exist_ok=True,mode=0o755)
            destination='/etc/pki/rpm-gpg/'+name
            atomic(destination,data,0o644)
            run(['rpm','--import',destination])
            return {'saved':destination}
        Path('/etc/apt/keyrings').mkdir(exist_ok=True,mode=0o755)
        atomic('/etc/apt/keyrings/'+name,data,0o644)
        return {'saved':'/etc/apt/keyrings/'+name}
    if action == 'patch':
        if rpm_backend():return rpm_module().patch(req.get('packages',[]))
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
    if request.get('action') in ('snapshot','events','ack','evidence','backups','operation-status','release-status'):
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
