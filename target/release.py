#!/usr/bin/python3
"""Durable release runner. Only fixed commands and reviewed configuration writes."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT=Path('/opt/drpatch')
LIB=Path('/usr/local/lib/mrpatchy')
OS_RELEASE=Path('/etc/os-release')
SERVICE_POLICY_PATH=Path('/usr/sbin/policy-rc.d')
PATHS=('/etc/nginx/','/etc/apache2/','/etc/postfix/','/etc/dovecot/','/etc/chrony/')
FORBIDDEN=('/etc/apt/','/etc/sudoers','/etc/pam.d/','/etc/systemd/','/etc/init','/etc/cron','/etc/mrpatchy/','/etc/ld.so','/etc/profile','/etc/bash','/etc/ssh/ssh_host_')
TRANSITIONS={'debian':{'11':('12','bullseye','bookworm'),'12':('13','bookworm','trixie')},'ubuntu':{'22.04':('24.04','jammy','noble'),'24.04':('26.04','noble','resolute')}}

def bridge():
    if str(LIB) not in sys.path:sys.path.insert(0,str(LIB))
    try:import bridge as module
    except ImportError:from target import bridge as module
    return module

def digest(value):return hashlib.sha256(value).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def os_info(text):
    return {k:v.strip().strip('"').strip("'") for k,v in (line.split('=',1) for line in text.splitlines() if '=' in line and not line.startswith('#'))}
def transition(inv):
    info=os_info(inv['os']);kind=info.get('ID');version=info.get('VERSION_ID','')
    # 64-bit Pi OS also reports ID=debian. Detect its vendor packages/sources.
    if kind=='raspbian' or any(x in inv.get('status','') for x in ('Package: raspberrypi-sys-mods\n','Package: raspi-config\n')) or any('raspberrypi.' in x or 'raspbian.' in x for x in inv.get('files',{}).values()):
        raise ValueError('Raspberry Pi OS major upgrades require a new-image migration; in-place upgrades are not supported')
    pair=TRANSITIONS.get(kind,{}).get(version)
    if not pair:raise ValueError('No supported adjacent stable release path for '+str(kind)+' '+version)
    return {'distribution':kind,'from_version':version,'version':pair[0],'from_suite':pair[1],'suite':pair[2]}
def conffiles(status_text):
    result={};package='';active=False
    for line in status_text.splitlines():
        if line.startswith('Package: '):package=line[9:].strip()
        if line=='Conffiles:':active=True;continue
        if active and line.startswith(' '):
            fields=line.split()
            if len(fields)==2 and re.fullmatch('[a-f0-9]{32}',fields[1]):result[fields[0]]={'package':package,'md5':fields[1]}
        else:active=False
    return result

def allowed_config(name):
    p=Path(name)
    return (name.startswith('/etc/') and str(p)==name and '..' not in p.parts and not name.startswith(FORBIDDEN)
            and name not in ('/etc/passwd','/etc/shadow','/etc/group','/etc/gshadow','/etc/environment','/etc/fstab','/etc/crypttab','/etc/rc.local')
            and not name.endswith(('.sh','.py','.pl','.rb','.lua','.js','.key','.pem')))
def safe_file(name):
    p=Path(name)
    if any(parent.is_symlink() for parent in [p,*p.parents]):raise ValueError('Symlink configuration is not supported: '+name)
    for parent in p.parents:
        parent_info=parent.stat()
        if parent_info.st_uid!=0 or parent_info.st_mode & 0o022:raise ValueError('Configuration parent is writable by non-root: '+str(parent))
    info=p.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_size>131072:
        raise ValueError('Configuration must be a root-owned regular file <=128 KiB: '+name)
    return p,info

def validator(name):
    if name=='/etc/ssh/sshd_config' or name.startswith('/etc/ssh/sshd_config.d/'):return ['/usr/sbin/sshd','-t']
    if name.startswith('/etc/nginx/'):return ['/usr/sbin/nginx','-t']
    if name.startswith('/etc/apache2/'):return ['/usr/sbin/apache2ctl','configtest']
    if name.startswith('/etc/postfix/'):return ['/usr/sbin/postfix','check']
    if name.startswith('/etc/dovecot/'):return ['/usr/bin/doveconf','-n']
    if name.startswith('/etc/chrony/'):return ['/usr/sbin/chronyd','-p','-f','/etc/chrony/chrony.conf']
    return None

def custom_validator():
    hook=Path('/etc/mrpatchy/release-validate')
    try:
        p,info=safe_file(str(hook))
        return bool(info.st_mode & 0o100)
    except (OSError,ValueError):return False

def fingerprint(inv):
    return digest(canonical({k:inv[k] for k in ('os','architecture','foreign_architectures','status','files','keys','machine_id')}))
def inspection():
    b=bridge();inv=b.handle({'action':'inventory'});blockers=[]
    try:destination=transition(inv)
    except ValueError as e:destination={};blockers.append(str(e))
    if Path('/usr/sbin/policy-rc.d').exists() or Path('/usr/sbin/policy-rc.d').is_symlink():blockers.append('An existing policy-rc.d needs a dedicated release adapter')
    if not Path('/run/systemd/system').is_dir():blockers.append('A systemd host is required')
    if shutil.disk_usage('/').free<8*1024**3:blockers.append('At least 8 GiB free on / is required')
    if shutil.disk_usage('/boot').free<512*1024**2:blockers.append('At least 512 MiB free on /boot is required')
    services=[]
    try:
        services=[line.split()[0] for line in b.run(['systemctl','list-units','--type=service','--state=running','--no-legend','--plain'],timeout=30).splitlines() if line.strip()]
        if len(services)>256 or any(not re.fullmatch(r'[A-Za-z0-9_.@:\\-]+\.service',unit) for unit in services):raise ValueError('Unsupported service inventory')
        if b.run(['dpkg','--audit'],timeout=30).strip():blockers.append('dpkg reports unfinished package configuration')
        health=b.handle({'action':'health'})
        if health['failed_units'] or not health['collector_active']:blockers.append('Resolve failed services before a release upgrade')
        if health.get('reboot_required'):blockers.append('Reboot pending updates before preparing a release upgrade')
    except Exception:blockers.append('Unable to verify package/service health')
    try:
        recovery=b.recovery_hook('probe','release-upgrade')
        if recovery.get('ready') is not True or recovery.get('release_upgrade_ready') is not True:blockers.append('Rollback adapter must attest release_upgrade_ready with tested boot and data recovery')
    except Exception:recovery={};blockers.append('A tested release-capable snapshot/rollback adapter is required')
    if destination.get('distribution')=='ubuntu':
        try:
            offer=b.run(['do-release-upgrade','-c'],timeout=180)
            if not re.search(r"['\"]"+re.escape(destination['version'])+r"(?:\.\d+)?(?: LTS)?['\"]",offer):blockers.append('Ubuntu has not offered the expected stable LTS upgrade')
        except Exception:blockers.append('Install update-manager-core and enable the supported LTS upgrade before planning')
    return {'inventory':inv,'fingerprint':fingerprint(inv),'target':destination,'blockers':blockers,'custom_validator':custom_validator(),'services':services,'boot_id':b.boot_id(),'runner_sha256':digest(Path(__file__).read_bytes())}

def configurations(names):
    known=conffiles(Path('/var/lib/dpkg/status').read_text());result={}
    if not isinstance(names,list) or len(names)>256:raise ValueError('Configuration review limit is 256 files')
    for name in names:
        if name not in known:raise ValueError('Only installed package conffiles may be read')
        try:
            path,info=safe_file(name)
            raw=path.read_bytes()
            if not allowed_config(name):
                if hashlib.md5(raw,usedforsecurity=False).hexdigest()!=known[name]['md5']:raise ValueError('Locally modified protected configuration requires manual migration')
                result[name]={'vendor_managed':True,'sha256':digest(raw),'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,**known[name]}
                continue
            content=raw.decode()
            result[name]={'content':content,'sha256':digest(content.encode()),'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,**known[name]}
        except (OSError,ValueError,UnicodeError) as e:result[name]={'error':str(e)[:300]}
    if len(canonical(result))>2_000_000:raise ValueError('Configuration review exceeds 2 MiB')
    return {'configs':result}

def directory(identifier):
    if not isinstance(identifier,str) or not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid release job ID')
    p=ROOT/'releases'/identifier;p.mkdir(parents=True,exist_ok=True,mode=0o700);return p

def read_state(identifier):
    p=directory(identifier)/'state.json'
    if not p.exists():return {'state':'absent'}
    return json.loads(p.read_text())

def save(folder,state):
    state['updated']=time.time();bridge().atomic(folder/'state.json',canonical(state))

def validate_plan(plan):
    if plan.get('format')!=1 or plan.get('expires',0)<time.time():raise ValueError('Release plan expired or unsupported')
    if len(canonical(plan))>3_000_000:raise ValueError('Release plan too large')
    if plan.get('blockers'):raise ValueError('Blocked release plan')
    if plan.get('runner_sha256')!=digest(Path(__file__).read_bytes()):raise ValueError('Release runner changed since planning')
    target=plan['target']
    if TRANSITIONS.get(target['distribution'],{}).get(target['from_version'])!=(target['version'],target['from_suite'],target['suite']):raise ValueError('Unsupported release transition')
    for edit in plan['edits']:
        if not allowed_config(edit['path']) or len(edit['after'].encode())>131072:raise ValueError('Invalid configuration edit')
    for name in plan['sources']:bridge().repo_path(name)

def check_drift(plan):
    inv=bridge().handle({'action':'inventory'})
    if fingerprint(inv)!=plan['inventory_hash']:raise ValueError('Target inventory/repository/trust changed; regenerate and approve a new plan')
    for entry in plan['configs']:
        path,info=safe_file(entry['path'])
        if digest(path.read_bytes())!=entry['sha256'] or [info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]!=[entry['uid'],entry['gid'],entry['mode']]:raise ValueError('Configuration changed: '+entry['path'])

def start(req):
    folder=directory(req['job_id']);plan=req['plan'];expected=req['digest']
    if digest(canonical(plan))!=expected:raise ValueError('Release plan digest mismatch')
    state=read_state(req['job_id'])
    if state['state']!='absent':
        if state['digest']!=expected:raise ValueError('Existing job has a different approved plan')
        return state # Never submit an already accepted job twice.
    validate_plan(plan);check_drift(plan)
    bridge().atomic(folder/'plan.json',canonical(plan))
    state={'state':'accepted','job':req['job_id'],'digest':expected,'boot_before':bridge().boot_id()};save(folder,state)
    # A detached service survives loss of the SSH session and central worker.
    try:bridge().run(['systemd-run','--unit=mrpatchy-release-'+req['job_id'],'--property=Type=exec','--property=TimeoutStartSec=infinity','/usr/bin/python3','-I',str(LIB/'release.py'),req['job_id']],timeout=30)
    except Exception:
        state['state']='recovery_required';state['error']='Service submission uncertain; inspect the target before reconciliation';save(folder,state);raise
    return state

def command(args,folder,timeout=10800):
    # stdin is closed: an unsupported interactive prompt must fail, never hang forever.
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'a','UCF_FORCE_CONFFOLD':'1','RELEASE_UPGRADER_NO_REBOOT':'1'}
    with (folder/'runner.log').open('ab') as log:
        os.chmod(folder/'runner.log',0o600)
        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=log,env=env,start_new_session=True)
        try:
            deadline=time.monotonic()+timeout
            while child.poll() is None:
                if time.monotonic()>deadline or log.tell()>64_000_000:raise RuntimeError('Upgrade command exceeded time/output budget')
                time.sleep(1)
            if child.returncode:raise RuntimeError('Upgrade command failed; inspect protected runner.log on target')
        finally:
            if child.poll() is None:
                import signal
                os.killpg(child.pid,signal.SIGKILL);child.wait()

def validate_configs(plan,folder):
    commands={tuple(validator(x['path'])) for x in plan['edits'] if validator(x['path'])}
    for cmd in sorted(commands):command(list(cmd),folder,120)
    if plan.get('custom_validation'):
        if not custom_validator():raise ValueError('Custom validation hook changed or unavailable')
        command(['/etc/mrpatchy/release-validate','validate',str(folder/'plan.json')],folder,300)

def schedule(folder,state,rollback=False):
    state.update(state='rollback_reboot_pending' if rollback else 'reboot_pending',boot_before=bridge().boot_id());save(folder,state)
    bridge().run(['systemd-run','--unit=mrpatchy-release-reboot-'+state['job'],'--on-active=15s','/usr/bin/systemctl','reboot'],timeout=30)
    return state

def rollback(identifier):
    folder=directory(identifier);state=read_state(identifier)
    if state['state'] in ('rolled_back','rollback_reboot_pending'):return state
    if not state.get('snapshot') or state.get('rollback_attempted'):raise ValueError('Rollback unavailable or already attempted; reconcile target')
    state.update(state='rolling_back',rollback_attempted=True);save(folder,state)
    result=bridge().recovery_hook('rollback',state['snapshot'])
    state['rollback']=result
    if result.get('reboot_required'):return schedule(folder,state,True)
    health=bridge().handle({'action':'health'})
    if health.get('failed_units') or not health.get('collector_active'):raise ValueError('Rollback service health failed')
    state['state']='rolled_back';save(folder,state);return state

SERVICE_POLICY=b'#!/bin/sh\n# Mr Patchy temporary release service-start guard\nexit 101\n'

def run_upgrade(identifier):
    folder=directory(identifier);state=read_state(identifier);plan=json.loads((folder/'plan.json').read_text())
    if state['state']!='accepted':raise RuntimeError('Refusing to replay a release upgrade')
    guarded=False
    try:
        validate_plan(plan);check_drift(plan)
        check=inspection()
        if check['blockers']:raise ValueError('; '.join(check['blockers']))
        state['state']='snapshotting';save(folder,state)
        snapshot=bridge().recovery_hook('snapshot',identifier).get('snapshot')
        if not isinstance(snapshot,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}',snapshot):raise ValueError('Invalid recovery snapshot')
        state.update(snapshot=snapshot,state='upgrading');save(folder,state)
        # Defer maintainer-script service starts until the reviewed configuration is installed.
        policy=SERVICE_POLICY_PATH
        with policy.open('xb') as stream:
            stream.write(SERVICE_POLICY);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o755)
        guarded=True
        if plan['target']['distribution']=='ubuntu':
            command(['do-release-upgrade','-f','DistUpgradeViewNonInteractive'],folder)
        else:
            for name,content in plan['sources'].items():bridge().atomic(name,content.encode(),0o644)
            command(['apt-get','-o','APT::Update::Error-Mode=any','update'],folder)
            # Verify the native resolver still produces the reviewed package transaction.
            raw=bridge().bounded(['apt-get','-s','dist-upgrade'],env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=300)[0]
            if parse_transaction(raw)!=plan['transaction']:raise ValueError('Repository candidates changed; rolling back rather than expanding approval')
            opts=['apt-get','-y','-o','Dpkg::Options::=--force-confold']
            command([*opts,'upgrade'],folder)
            specs=[x['package']+'='+x['version'] if x['action']=='install' else x['package']+'-' for x in plan['transaction']]
            command([*opts,'install','--',*specs],folder)
        info=os_info(OS_RELEASE.read_text())
        if info.get('ID')!=plan['target']['distribution'] or info.get('VERSION_ID')!=plan['target']['version']:raise ValueError('Expected release was not installed')
        state['state']='configuring';save(folder,state)
        for edit in plan['edits']:
            path,info=safe_file(edit['path'])
            # Conffile machinery may have replaced a file. Never overwrite an unexpected result.
            if digest(path.read_bytes()) not in (edit['before_sha256'],edit['vendor_sha256']):raise ValueError('Unexpected post-upgrade configuration: '+edit['path'])
            bridge().atomic(path,edit['after'].encode(),edit['mode']);os.chown(path,edit['uid'],edit['gid'])
        validate_configs(plan,folder)
        if bridge().run(['dpkg','--audit'],timeout=60).strip():raise ValueError('dpkg audit failed before reboot')
        schedule(folder,state)
    except Exception as error:
        state=read_state(identifier);state['error']=str(error)[:1000];save(folder,state)
        if state.get('snapshot'):
            try:rollback(identifier);return
            except Exception as rollback_error:state=read_state(identifier);state['rollback_error']=str(rollback_error)[:500]
        state['state']='recovery_required';save(folder,state)
    finally:
        if guarded:
            policy=SERVICE_POLICY_PATH
            if policy.is_file() and not policy.is_symlink() and policy.read_bytes()==SERVICE_POLICY:policy.unlink()

def parse_transaction(output):
    rows=[]
    for line in output.splitlines():
        if line.startswith('Inst '):
            match=re.match(r'Inst (\S+)(?: \[([^\]]+)\])? \((\S+)',line)
            if not match:raise ValueError('Unrecognized APT transaction')
            rows.append({'action':'install','package':match[1].split(':')[0],'version':match[3]})
        elif line.startswith('Remv '):rows.append({'action':'remove','package':line.split()[1].split(':')[0],'version':''})
    return sorted(rows,key=lambda x:(x['package'],x['action'],x['version']))

def verify(identifier):
    folder=directory(identifier);state=read_state(identifier);plan=json.loads((folder/'plan.json').read_text())
    if state['state']=='complete':return state
    if state['state']!='reboot_pending' or state['boot_before']==bridge().boot_id():raise ValueError('Release reboot has not been observed')
    inv=bridge().handle({'action':'inventory'});info=os_info(inv['os'])
    if info.get('VERSION_ID')!=plan['target']['version'] or info.get('ID')!=plan['target']['distribution']:raise ValueError('Post-reboot release mismatch')
    validate_configs(plan,folder)
    if bridge().run(['dpkg','--audit'],timeout=60).strip():raise ValueError('dpkg audit failed after reboot')
    health=bridge().handle({'action':'health'})
    if health['failed_units'] or not health['collector_active']:raise ValueError('Services not healthy after reboot')
    for unit in plan.get('services',[]):
        if bridge().run(['systemctl','is-active','--',unit],timeout=15).strip()!='active':raise ValueError('Previously running service did not recover: '+unit)
    for edit in plan['edits']:
        if digest(Path(edit['path']).read_bytes())!=digest(edit['after'].encode()):raise ValueError('Applied configuration changed after reboot')
    state.update(state='complete',health=health,boot_after=bridge().boot_id());save(folder,state);return state

if __name__=='__main__':
    os.umask(0o077)
    with (ROOT/'bridge.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        run_upgrade(sys.argv[1])
