"""Bounded maintenance of enrolled helpers; never repair a changed trust path."""
import hashlib
import json
import time
from sqlalchemy import select,func
from .db import Setting,Job,audit
from . import ssh,operations

TRUST_PATHS=('/usr/local/lib/mrpatchy/bridge.py','/etc/sudoers.d/mrpatchy','/opt/drpatch/.ssh/authorized_keys')
OPTIONAL='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf'
DEFAULT_POLICY={'auto_upgrade':False,'auto_repair':False}

def policy(s,host_id):
    row=s.get(Setting,'agent-policy:'+host_id)
    return {**DEFAULT_POLICY,**(row.value if row else {})}

def release_id(host):
    try:return hashlib.sha256(json.dumps(ssh.expected_files(host),sort_keys=True).encode()).hexdigest()
    except (OSError,ValueError):return None

def public(s,host):
    row=s.get(Setting,'agent-status:'+host.id)
    status=dict(row.value) if row else {'state':'unknown','checked':0,'issues':[],'repairable':False}
    status['stale']=time.time()-status.get('checked',0)>600
    try:enrolled_outdated=bool(host.baseline) and any(host.baseline.get(p)!=v for p,v in ssh.expected_files(host).items())
    except (OSError,ValueError):enrolled_outdated=None
    return {'policy':policy(s,host.id),'status':status,'release':release_id(host),'enrolled_outdated':enrolled_outdated}

def assess(host,report):
    current=ssh.expected_files(host);baseline=host.baseline
    result={'state':'current','issues':[],'repairable':True,'outdated':False,'drifted':False}
    def issue(path,kind):result['issues'].append({'path':path,'kind':kind})
    if not isinstance(report,dict) or report.get('version')!=1 or not isinstance(report.get('files'),dict):
        raise ValueError('Unsupported agent status receipt')
    files=report['files']
    if not baseline:issue('enrollment','missing_baseline');result['repairable']=False
    for path,expected in current.items():
        observed=files.get(path,{})
        digest=observed.get('sha256')
        if digest!=expected:
            if baseline.get(path)==digest and digest:
                result['outdated']=True;issue(path,'outdated')
            else:result['drifted']=True;issue(path,'unexpected_content_or_missing')
        mode=0o440 if path=='/etc/sudoers.d/mrpatchy' else 0o644
        if any(observed.get(k)!=v for k,v in {'uid':0,'gid':0,'mode':mode}.items()):
            result['drifted']=True;issue(path,'ownership_or_permissions')
        if observed.get('unsafe'):result['repairable']=False
        if path==OPTIONAL and digest!=expected:result['repairable']=False
        if path in (*TRUST_PATHS,OPTIONAL) and (not baseline.get(path) or digest!=baseline[path] or any(observed.get(k)!=v for k,v in {'uid':0,'gid':0,'mode':mode}.items())):
            result['repairable']=False
    if report.get('directories_secure') is not True:
        issue('installation','unsafe_parent_directory');result['repairable']=False
    expected_dropins=[OPTIONAL] if OPTIONAL in baseline else []
    if report.get('unit_path')!='/etc/systemd/system/mrpatchy-agent.service' or report.get('dropins')!=expected_dropins:
        issue('systemd','unexpected_unit_or_dropins');result['repairable']=False
    if report.get('active') is not True or report.get('enabled') is not True:
        issue('collector','service_inactive_or_disabled');result['drifted']=True
    if result['issues']:result['state']='blocked' if not result['repairable'] else 'drifted' if result['drifted'] else 'outdated'
    return result

def inspect(s,host,*,queue=True):
    try:
        report=ssh.call(host,{'action':'agent-status'},timeout=30)
        status=assess(host,report)
    except Exception as error:
        report=None
        status={'state':'unavailable','repairable':False,'outdated':False,'drifted':False,
                'issues':[{'path':'verification','kind':type(error).__name__+': live agent verification unavailable; check connection or redeploy current helpers from a trusted console'}]}
    status.update(checked=time.time(),release=release_id(host),report=report)
    key='agent-status:'+host.id;previous=s.get(Setting,key)
    if not previous or previous.value.get('state')!=status['state']:
        audit(s,'agent health changed',host.id+' '+status['state'])
    if previous:previous.value=status
    else:s.add(Setting(key=key,value=status))
    s.commit()
    if queue:maybe_queue(s,host,status)
    return status

def allowed(policy,status):
    return status.get('repairable') and (status.get('outdated') or status.get('drifted')) and (not status.get('outdated') or policy['auto_upgrade']) and (not status.get('drifted') or policy['auto_repair'])

def maybe_queue(s,host,status):
    if not allowed(policy(s,host.id),status) or operations.host_quarantined(s,host.id):return
    if s.scalar(select(Job.id).where(Job.host_id==host.id,Job.state.in_(['queued','running'])).limit(1)):return
    now=time.time()
    recent=list(s.scalars(select(Job).where(Job.host_id==host.id,Job.action=='agent-update',Job.created>now-86400)))
    if len(recent)>=2 or any(j.created>now-3600 for j in recent):return
    from .worker import enqueue
    enqueue(s,host.id,'agent-update',{'automatic':True,'release':release_id(host)})

def update(s,host,job):
    if job.payload.get('release')!=release_id(host):raise ValueError('Controller release changed; queue a fresh agent review')
    status=inspect(s,host,queue=False)
    if status['state']=='current':return {'state':'current','changed':False}
    if not status.get('repairable'):raise ValueError('Agent trust path cannot be verified; recover through a trusted console')
    if job.payload.get('automatic') and not allowed(policy(s,host.id),status):raise ValueError('Automatic agent maintenance is disabled for this change')
    expected=ssh.expected_files(host)
    if isinstance(job,Job):
        job.output=json.dumps({'before':status});s.commit()
    result=ssh.deploy(host)
    # The new bridge must independently verify the entire intended manifest.
    report=ssh.call(host,{'action':'agent-status'},timeout=30)
    old=host.baseline
    host.baseline=expected
    verified=assess(host,report)
    if verified['state']!='current':
        host.baseline=old
        raise ValueError('Agent update could not be verified; previous baseline retained')
    s.commit()
    inspect(s,host,queue=False)
    audit(s,'agent maintenance verified',host.id+' '+release_id(host))
    return {'before':status,'deployment':result,'verification':report,'state':'current','changed':True}
