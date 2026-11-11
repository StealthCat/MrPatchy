"""Read-only recovery readiness derived from operator-supplied drill receipts (issue #345 slice).

A receipt records evidence that something already happened; recording one never
starts a backup, restore, stop or activation. Receipts hold no key material:
only non-secret identities and custody attestations are accepted. Unknown fields
are rejected. These are operator attestations, not independently executed drills.
"""
import math
import time
import uuid
import re

STAGES=('backup','archive_verification','isolated_restore','boot_recovery','application_recovery')
REQUIRED=('backup','archive_verification','isolated_restore','application_recovery')
MAX_AGE={'backup':48*3600,'archive_verification':48*3600,'isolated_restore':35*86400,
         'boot_recovery':35*86400,'application_recovery':35*86400}
CUSTODY=('external','local','unknown')
MAX_RECEIPTS=100
MAX_ITEMS=20
CLOCK_SKEW=300
VERSION=2
BINDING=('backup_id','archive_sha256','environment','adapter','database_id','trust_id','key_fingerprint')
PARENT={'archive_verification':'backup','isolated_restore':'archive_verification',
        'boot_recovery':'isolated_restore','application_recovery':'isolated_restore'}


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
    allowed={'stage','result','completed','environment','adapter','declared_scope','verified','key_custody','gaps',
             'version','backup_id','archive_sha256','database_id','trust_id','key_fingerprint','key_verified_at','parent_id'}
    if not isinstance(data,dict) or set(data)-allowed:raise ValueError('Unsupported receipt fields')
    if type(data.get('version')) is not int or data['version']!=VERSION:raise ValueError('A version 2 bound receipt is required')
    stage=data.get('stage')
    if stage not in STAGES:raise ValueError('Unknown stage')
    if data.get('result') not in ('success','failure'):raise ValueError('result must be success or failure')
    done=data.get('completed')
    if isinstance(done,bool) or not isinstance(done,(int,float)) or not math.isfinite(done) or done<=0:raise ValueError('completed must be an epoch time')
    if done>now+CLOCK_SKEW:raise ValueError('completed is in the future')
    custody=data.get('key_custody','unknown')
    if custody not in CUSTODY:raise ValueError('key_custody must be external, local or unknown')
    identity={name:text(data.get(name),80,name) for name in ('backup_id','database_id','trust_id')}
    for name in ('archive_sha256','key_fingerprint'):
        value=data.get(name)
        if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):raise ValueError(name+' must be a lowercase SHA-256 identity')
        identity[name]=value
    checked=data.get('key_verified_at')
    if type(checked) not in (int,float) or not math.isfinite(checked) or not 0<checked<=done:
        raise ValueError('key_verified_at must be a valid verification time before receipt completion')
    parent=data.get('parent_id','')
    if stage=='backup':
        if parent:raise ValueError('A backup receipt has no parent')
    elif not isinstance(parent,str) or not re.fullmatch('[a-f0-9]{32}',parent):raise ValueError('A drill receipt needs its parent receipt ID')
    return {'version':VERSION,**identity,'key_verified_at':float(checked),'parent_id':parent,
            'stage':stage,'result':data['result'],'completed':float(done),
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
    def completed(item):
        value=item.get('completed')
        return value if type(value) in (int,float) and math.isfinite(value) else float('inf')
    for stage in STAGES:
        mine=[x for x in items if x['stage']==stage]
        if mine:latest[stage]=max(mine,key=completed)
    stages={};blockers=[]
    backup=latest.get('backup')
    for stage in STAGES:
        r=latest.get(stage)
        if r is None:state='missing'
        else:
            try:receipt({k:v for k,v in r.items() if k not in ('id','recorded')},now)
            except (ValueError,TypeError):state='unknown'
            else:
                parent=latest.get(PARENT.get(stage))
                if r.get('result')!='success':state='failed'
                elif now-r['completed']>MAX_AGE[stage]:state='stale'
                elif stage!='backup' and (not backup or any(r.get(k)!=backup.get(k) for k in BINDING)):
                    state='mismatched'
                elif stage!='backup' and (not parent or not parent.get('id') or r['parent_id']!=parent['id']
                        or completed(parent)>r['completed']):state='unbound'
                else:state='ok'
        stages[stage]={'state':state,'required':stage in REQUIRED,'max_age_seconds':MAX_AGE[stage],
                       'receipt':{k:r[k] for k in ('id','version','completed',*BINDING,'parent_id','verified','gaps') if k in r} if r else None}
        if stage in REQUIRED and state!='ok':blockers.append(f'{stage}: {state}')
    scope=set(backup.get('declared_scope',[])) if backup and stages['backup']['state']=='ok' else set()
    covered=set()
    for stage in ('isolated_restore','application_recovery'):
        r=latest.get(stage)
        if r and stages[stage]['state']=='ok':covered|=set(r.get('verified',[]))
    uncovered=sorted(scope-covered)
    if backup and scope and uncovered:blockers.append('declared scope not verified by a restore drill: '+', '.join(uncovered))
    custody=backup.get('key_custody','unknown') if backup and stages['backup']['state']=='ok' else 'unknown'
    if custody!='external':blockers.append('encryption-key custody is not confirmed outside the protected deployment')
    checked=backup.get('key_verified_at') if backup else None
    if type(checked) not in (int,float) or not math.isfinite(checked) or not 0<=now-checked<=MAX_AGE['isolated_restore']:
        blockers.append('encryption-key verification is missing or stale')
    return {'ready':not blockers,'stages':stages,'declared_scope':sorted(scope),'unverified_scope':uncovered,
            'key_custody':custody,'blockers':blockers,'generated':now,
            'version':VERSION,'evidence_source':'operator_attestation',
            'note':'Matched, current operator attestations for one backup/archive/database/trust/key chain; not independent execution or proof that a deployment is recoverable. An archive checksum alone is never sufficient.'}
