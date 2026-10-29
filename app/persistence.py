"""Compare bounded, immutable startup inventories; differences are not malware verdicts."""
from . import host_lifecycle
import re
from pathlib import PurePosixPath


def path_ok(value):
    return (isinstance(value,str) and 1<len(value)<=4096 and value.startswith('/')
            and not value.startswith('//') and '\x00' not in value
            and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts)


def validate(inventory):
    if not isinstance(inventory,dict) or inventory.get('state') not in ('collected','incomplete'):
        raise ValueError('Invalid persistence inventory')
    scope=inventory.get('scope');entries=inventory.get('entries');gaps=inventory.get('gaps');missing=inventory.get('missing_roots')
    if not isinstance(scope,list) or not 1<=len(scope)<=32 or not all(path_ok(p) for p in scope) or len(set(scope))!=len(scope):
        raise ValueError('Invalid persistence scope')
    if not isinstance(entries,list) or len(entries)>256 or not isinstance(gaps,list) or len(gaps)>50 or not all(isinstance(g,str) and len(g)<=8192 for g in gaps):
        raise ValueError('Invalid persistence coverage')
    if not isinstance(missing,list) or any(p not in scope for p in missing):raise ValueError('Invalid missing persistence roots')
    if type(inventory.get('skipped')) is not int or inventory['skipped']<0:raise ValueError('Invalid persistence skipped count')
    seen=set()
    for row in entries:
        if not isinstance(row,dict) or not path_ok(row.get('path')):raise ValueError('Invalid persistence path')
        path=row['path']
        if path in seen or not any(path==root or path.startswith(root+'/') for root in scope):raise ValueError('Duplicate or out-of-scope persistence entry')
        if any(path==root or path.startswith(root+'/') for root in missing):raise ValueError('Entry under missing persistence root')
        seen.add(path)
        if any(type(row.get(k)) is not int or row[k]<0 for k in ('uid','gid','mode','size','mtime_ns')) or row['mode']>0o7777:
            raise ValueError('Invalid persistence metadata')
        if row.get('kind')=='regular':
            if not isinstance(row.get('sha256'),str) or not re.fullmatch('[a-f0-9]{64}',row['sha256']):raise ValueError('Invalid persistence hash')
        elif row.get('kind')=='symlink':
            if not isinstance(row.get('target'),str) or not 1<=len(row['target'])<=4096 or '\x00' in row['target']:raise ValueError('Invalid persistence link')
        else:raise ValueError('Invalid persistence entry type')
    if inventory['state']=='collected' and (gaps or inventory['skipped']):raise ValueError('Persistence coverage contradicts collected state')


def compare(before,after):
    result={'state':'unavailable','changes':[], 'note':'No comparable complete prior inventory; absence is not evidence of removal.'}
    try:validate(before);validate(after)
    except ValueError:return result
    if before['state']!='collected' or after['state']!='collected':return result
    if set(before['scope'])!=set(after['scope']):
        return {**result,'note':'Inventory scope changed; collect another complete inventory with the same scope.'}
    old={r['path']:r for r in before['entries']};new={r['path']:r for r in after['entries']}
    changes=[]
    fields=('kind','sha256','target','uid','gid','mode','size')
    for path in sorted(old.keys()|new.keys()):
        previous=old.get(path);current=new.get(path)
        changed=[key for key in fields if (previous or {}).get(key)!=(current or {}).get(key)]
        if previous is None or current is None or changed:
            changes.append({'path':path,'kind':'added' if previous is None else 'removed' if current is None else 'changed',
                            'fields':changed,'before':previous,'after':current})
    return {'state':'compared','changes':changes,'note':'Observed changes between complete inventories, not an approved baseline or a malware verdict. Modification time alone is ignored.'}


MAX_AGE=86400


def latest(s,host_id):
    from sqlalchemy import select
    from .incidents import Inspection
    return s.scalar(select(Inspection).where(Inspection.host_id==host_id,
        Inspection.report['persistence']['state'].as_string().is_not(None))
        .order_by(Inspection.created.desc(),Inspection.id.desc()).limit(1))


def status(s,host_id):
    import time
    from .db import Setting
    from .incidents import PersistenceBaseline,Inspection,digest
    active=s.get(Setting,'persistence-baseline:'+host_id)
    baseline=s.get(PersistenceBaseline,active.value['id']) if active else None
    row=latest(s,host_id)
    inv=row.report.get('persistence') if row else None
    eligible=False
    try:
        validate(inv)
        eligible=inv['state']=='collected' and 0<=time.time()-row.created<=MAX_AGE
    except ValueError:pass
    before=s.get(Inspection,baseline.inspection_id) if baseline else None
    trusted=bool(baseline and baseline.host_id==host_id and before and before.host_id==host_id and digest(before.report.get('persistence'))==baseline.evidence_digest)
    comparison=compare(before.report.get('persistence') if trusted else None,inv)
    if comparison['state']=='compared':comparison['note']='Compared with the administrator-reviewed startup baseline; matches are not a clean-host verdict.'
    if active and not trusted:state='unavailable'
    elif not baseline:state='not_configured'
    elif not row or not 0<=time.time()-row.created<=MAX_AGE:state='stale'
    elif comparison['state']!='compared':state='unavailable'
    else:state='drifted' if comparison['changes'] else 'matches'
    return {'state':state,'baseline':({'id':baseline.id,'inspection_id':baseline.inspection_id,'actor':baseline.actor,
        'created':baseline.created,'reason':baseline.reason} if baseline else None),
        'latest':({'id':row.id,'created':row.created,'digest':digest(inv),'inventory':inv} if row else None),
        'eligible':eligible,'max_age_seconds':MAX_AGE,'comparison':comparison}


def approve(s,host_id,inspection_id,evidence_digest,expected,reason,actor):
    import uuid
    from .db import Setting,audit
    from .incidents import PersistenceBaseline
    current=status(s,host_id)
    actual=current['baseline']['id'] if current['baseline'] else ''
    if actual!=expected:raise ValueError('Baseline changed; refresh and review again')
    row=current['latest']
    if not current['eligible'] or not row or row['id']!=inspection_id or row['digest']!=evidence_digest:
        raise ValueError('Inspection changed, expired or incomplete; collect and review a fresh complete inventory')
    if current['baseline'] and current['baseline']['inspection_id']==inspection_id:raise ValueError('This inventory is already approved')
    reason=reason.strip()
    if not 10<=len(reason)<=4000:raise ValueError('Provide a review reason of 10–4000 characters')
    baseline=PersistenceBaseline(id=str(uuid.uuid4()),host_id=host_id,inspection_id=inspection_id,
        evidence_digest=evidence_digest,actor=actor,reason=reason)
    s.add(baseline);s.flush()
    s.merge(Setting(key='persistence-baseline:'+host_id,value={'id':baseline.id}))
    audit(s,'persistence baseline approved',host_id+' '+baseline.id+' '+inspection_id+' '+actor)
    return baseline.id


DEFAULT_MONITOR={'custom_paths':[],'enabled':False,'interval_hours':12,'link_incidents':False,'revision':''}


def monitor_policy(s,host_id):
    from .db import Setting
    row=s.get(Setting,'persistence-monitor:'+host_id)
    return {**DEFAULT_MONITOR,**(row.value if row else {})}


def schedule_tick(now=None):
    import time
    from sqlalchemy import select
    from .coordination import Lock
    from .db import Session,Setting,Host,Job
    from .worker import enqueue
    now=time.time() if now is None else now
    # The manual inspection endpoint uses this same queue lock.
    with Lock('security-inspection-queue'),Session() as s:
        for setting in s.scalars(select(Setting).where(Setting.key.like('persistence-monitor:%'))):
            policy=setting.value;host_id=setting.key.split(':',1)[1];host=s.get(Host,host_id)
            if not policy.get('enabled') or not host_lifecycle.active(host) or host.state=='enrolling' or not host.fingerprint:continue
            from .operations import host_quarantined
            if host_quarantined(s,host_id):continue
            if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state.in_(['queued','running','recovery_required'])).limit(1)):continue
            last=s.scalar(select(Job).where(Job.host_id==host_id,Job.action=='security-inspect').order_by(Job.created.desc()).limit(1))
            if last and now-last.created<policy['interval_hours']*3600:continue
            payload={'packages':[],'persistence':True,'_persistence_policy':policy['revision']}
            if policy.get('custom_paths'):payload['custom_paths']=policy['custom_paths']
            enqueue(s,host_id,'security-inspect',payload)


def record_changes(s,host_id,inspection_id):
    import time
    from .incidents import PersistenceIncident,PersistenceDetection,digest
    if not monitor_policy(s,host_id)['link_incidents']:return
    assessment=status(s,host_id)
    if assessment['state']!='drifted' or assessment['latest']['id']!=inspection_id:return
    changes=assessment['comparison']['changes'];baseline_id=assessment['baseline']['id']
    # Modification times do not define change identity; they can vary on repeats.
    stable=[{**c,**{side:({k:v for k,v in c[side].items() if k!='mtime_ns'} if c[side] else None) for side in ('before','after')}} for c in changes]
    identifier=digest({'host':host_id,'baseline':baseline_id,'changes':stable})
    row=s.get(PersistenceIncident,identifier)
    if row:
        row.updated=max(time.time(),row.updated+.000001);row.state='open'
    else:
        row=PersistenceIncident(id=identifier,host_id=host_id,baseline_id=baseline_id,evidence={'changes':changes,'classification':'startup_change_not_malware_verdict'})
        s.add(row)
    s.add(PersistenceDetection(inspection_id=inspection_id,incident_id=identifier))
