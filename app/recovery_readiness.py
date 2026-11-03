"""Read-only recovery readiness derived from operator-supplied drill receipts (issue #345 slice).

A receipt records evidence that something already happened; recording one never
starts a backup, restore, stop or activation. Receipts hold no key material:
only a custody status word is accepted and unknown fields are rejected.
"""
import math
import time
import uuid

STAGES=('backup','archive_verification','isolated_restore','boot_recovery','application_recovery')
REQUIRED=('backup','archive_verification','isolated_restore','application_recovery')
MAX_AGE={'backup':48*3600,'archive_verification':48*3600,'isolated_restore':35*86400,
         'boot_recovery':35*86400,'application_recovery':35*86400}
CUSTODY=('external','local','unknown')
MAX_RECEIPTS=100
MAX_ITEMS=20
CLOCK_SKEW=300


def text(value,limit,label):
    if not isinstance(value,str) or not value.strip() or len(value)>limit or any(ord(c)<32 for c in value):
        raise ValueError(f'{label} must be 1-{limit} printable characters')
    return value.strip()


def names(value,label,required=False):
    if not isinstance(value,list) or len(value)>MAX_ITEMS or (required and not value):
        raise ValueError(f'{label} must be a list of at most {MAX_ITEMS} entries'+(' and not empty' if required else ''))
    return sorted({text(v,60,label) for v in value})


def receipt(data,now=None):
    """Validate and normalise one receipt; raise ValueError on anything unexpected."""
    now=time.time() if now is None else now
    allowed={'stage','result','completed','environment','adapter','declared_scope','verified','key_custody','gaps'}
    if not isinstance(data,dict) or set(data)-allowed:raise ValueError('Unsupported receipt fields')
    stage=data.get('stage')
    if stage not in STAGES:raise ValueError('Unknown stage')
    if data.get('result') not in ('success','failure'):raise ValueError('result must be success or failure')
    done=data.get('completed')
    if isinstance(done,bool) or not isinstance(done,(int,float)) or not math.isfinite(done) or done<=0:raise ValueError('completed must be an epoch time')
    if done>now+CLOCK_SKEW:raise ValueError('completed is in the future')
    custody=data.get('key_custody','unknown')
    if custody not in CUSTODY:raise ValueError('key_custody must be external, local or unknown')
    return {'stage':stage,'result':data['result'],'completed':float(done),
            'environment':text(data.get('environment'),80,'environment'),'adapter':text(data.get('adapter'),80,'adapter'),
            'declared_scope':names(data.get('declared_scope',[]),'declared_scope',stage=='backup' and data['result']=='success'),
            'verified':names(data.get('verified',[]),'verified'),'key_custody':custody,
            'gaps':names(data.get('gaps',[]),'gaps')}


def add(items,data,now=None):
    """Return the bounded receipt list with one new validated receipt appended."""
    item={'id':uuid.uuid4().hex,'recorded':time.time() if now is None else now,**receipt(data,now)}
    return ([x for x in items if isinstance(x,dict)]+[item])[-MAX_RECEIPTS:],item


def readiness(items,now=None):
    now=time.time() if now is None else now
    items=[x for x in items if isinstance(x,dict) and x.get('stage') in STAGES]
    latest={}
    for stage in STAGES:
        mine=[x for x in items if x['stage']==stage]
        if mine:latest[stage]=max(mine,key=lambda x:x.get('completed',0))
    stages={};blockers=[]
    for stage in STAGES:
        r=latest.get(stage)
        if r is None:state='missing'
        elif r.get('result')!='success':state='failed'
        elif now-r.get('completed',0)>MAX_AGE[stage]:state='stale'
        else:state='ok'
        stages[stage]={'state':state,'required':stage in REQUIRED,'max_age_seconds':MAX_AGE[stage],
                       'receipt':{k:r[k] for k in ('id','completed','environment','adapter','verified','gaps') if k in r} if r else None}
        if stage in REQUIRED and state!='ok':blockers.append(f'{stage}: {state}')
    backup=latest.get('backup')
    scope=set(backup.get('declared_scope',[])) if backup and backup.get('result')=='success' else set()
    covered=set()
    for stage in ('isolated_restore','application_recovery'):
        r=latest.get(stage)
        if r and stages[stage]['state']=='ok':covered|=set(r.get('verified',[]))
    uncovered=sorted(scope-covered)
    if backup and scope and uncovered:blockers.append('declared scope not verified by a restore drill: '+', '.join(uncovered))
    custody=backup.get('key_custody','unknown') if backup else 'unknown'
    if custody=='unknown':blockers.append('encryption-key custody is not confirmed')
    return {'ready':not blockers,'stages':stages,'declared_scope':sorted(scope),'unverified_scope':uncovered,
            'key_custody':custody,'blockers':blockers,'generated':now,
            'note':'Readiness requires backup, archive verification, an isolated restore and application recovery evidence; an archive checksum alone is never sufficient.'}
