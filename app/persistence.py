"""Compare bounded, immutable startup inventories; differences are not malware verdicts."""
from . import host_lifecycle
import re
from pathlib import PurePosixPath


def path_ok(value):
    return (isinstance(value,str) and 1<len(value)<=4096 and value.startswith('/')
            and not value.startswith('//') and '\x00' not in value
            and str(PurePosixPath(value))==value and '..' not in PurePosixPath(value).parts)


CRON_FILE_JOBS=64
CRON_TOTAL_JOBS=256
CRON_COMMAND_LIMIT=512


def validate_cron(cron):
    """Strictly validate optional parsed crontab jobs reported by newer agents."""
    if not isinstance(cron,dict) or set(cron)!={'format','jobs','unparsed','environment','truncated'} or cron['format'] not in ('system','user'):
        raise ValueError('Invalid cron job inventory')
    if any(type(cron[k]) is not int or cron[k]<0 for k in ('unparsed','environment')) or type(cron['truncated']) is not bool:
        raise ValueError('Invalid cron job inventory')
    jobs=cron['jobs']
    if not isinstance(jobs,list) or len(jobs)>CRON_FILE_JOBS:raise ValueError('Invalid cron job inventory')
    for job in jobs:
        if not isinstance(job,dict) or set(job)!={'line','schedule','account','command','redacted','command_truncated','stdin'}:raise ValueError('Invalid cron job')
        if type(job['line']) is not int or job['line']<1 or type(job['redacted']) is not bool or type(job['command_truncated']) is not bool or type(job['stdin']) is not bool:raise ValueError('Invalid cron job')
        if not isinstance(job['schedule'],str) or not 1<=len(job['schedule'])<=400 or not isinstance(job['command'],str) or not 1<=len(job['command'])<=CRON_COMMAND_LIMIT:
            raise ValueError('Invalid cron job')
        if job['account'] is not None and (not isinstance(job['account'],str) or not 1<=len(job['account'])<=33):raise ValueError('Invalid cron job')
        if any('\x00' in job[k] for k in ('schedule','command')):raise ValueError('Invalid cron job')
    return len(jobs)


AT_SPOOL_DIR='/var/spool/cron/atjobs'
AT_COMMAND_LINES=32
AT_KEYS={'queue','job','scheduled_at','running','uid','gid','account','commands','environment','parsed','truncated','redacted'}


def validate_at(at,path):
    """Strictly validate an optional parsed at job reported by newer agents for a spool file."""
    name=path.rsplit('/',1)
    if len(name)!=2 or name[0]!=AT_SPOOL_DIR or not re.fullmatch(r'[a-zA-Z=][0-9a-f]{5}[0-9a-f]{8}',name[1]):raise ValueError('At job outside the at spool')
    if not isinstance(at,dict) or set(at)!=AT_KEYS:raise ValueError('Invalid at job')
    letter=name[1][0]
    if at['queue']!=letter or at['running'] is not (letter=='=') or at['job']!=int(name[1][1:6],16) or at['scheduled_at']!=int(name[1][6:],16)*60:
        raise ValueError('At job does not match its spool file name')
    if any(type(at[k]) is not bool for k in ('running','parsed','truncated','redacted')) or type(at['environment']) is not int or not 0<=at['environment']<=1000000:
        raise ValueError('Invalid at job')
    for key in ('uid','gid'):
        if at[key] is not None and (type(at[key]) is not int or not 0<=at[key]<2**32):raise ValueError('Invalid at job')
    if at['account'] is not None and (not isinstance(at['account'],str) or not re.fullmatch(r'[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}\$?',at['account'])):raise ValueError('Invalid at job')
    commands=at['commands']
    if not isinstance(commands,list) or len(commands)>AT_COMMAND_LINES or (commands and not at['parsed']) or (at['parsed'] and at['uid'] is None):
        raise ValueError('Invalid at job')
    if any(not isinstance(c,str) or not 1<=len(c)<=CRON_COMMAND_LIMIT or '\x00' in c for c in commands):raise ValueError('Invalid at job')


def metadata(row):
    """Entry metadata without parsed cron/at job detail, for comparisons and incident evidence."""
    return {k:v for k,v in row.items() if k not in ('cron','at')} if row is not None else None


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
    seen=set();jobs=0
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
        if 'cron' in row:
            if row['kind']!='regular':raise ValueError('Cron jobs require a regular file')
            jobs+=validate_cron(row['cron'])
        if 'at' in row:
            if row['kind']!='regular':raise ValueError('At jobs require a regular file')
            validate_at(row['at'],path)
    if jobs>CRON_TOTAL_JOBS:raise ValueError('Too many cron jobs')
    if inventory['state']=='collected' and (gaps or inventory['skipped']):raise ValueError('Persistence coverage contradicts collected state')


def compare(before,after):
    result={'state':'unavailable','changes':[], 'note':'No comparable complete prior inventory; absence is not evidence of removal.'}
    try:validate(before);validate(after)
    except ValueError:return result
    if before['state']!='collected' or after['state']!='collected':return result
    if set(before['scope'])!=set(after['scope']):
        return {**result,'note':'Inventory scope changed; collect another complete inventory with the same scope.'}
    # Parsed cron detail is administrator-view data; change evidence stays metadata-only.
    old={r['path']:metadata(r) for r in before['entries']};new={r['path']:metadata(r) for r in after['entries']}
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


def review(s, host_id):
    """Read-only evidence review; file authenticity never grants approval."""
    current = status(s, host_id)
    latest_row = current['latest']
    current['file_review'] = assess_inventory(
        s, host_id, latest_row['inventory'] if latest_row else None)
    from .incidents import digest
    current['review_digest'] = digest(current['file_review'])
    return current


def assess_inventory(s, host_id, inventory):
    from . import file_status, known_good, ai_assessments
    from .db import config
    # Resolve authenticated bytes before checking the strict reuse contract.
    proofs = file_status.repositories(s, host_id)
    result = {'order': file_status.ORDER, 'items': [], 'coverage': 'unavailable',
        'note': 'Authentic file bytes do not establish safe startup behavior. '
                'Startup metadata lacks the complete process context required by the '
                'known-good database. Unresolved changes may be investigated with an '
                'explicitly requested AI plan; baseline approval remains manual.'}
    try:
        validate(inventory)
    except ValueError:
        return result
    result['coverage'] = inventory['state']
    result['gaps'] = inventory['gaps']
    result['skipped'] = inventory['skipped']
    result['missing_roots'] = inventory['missing_roots']
    cfg = config(s)
    policy = ai_assessments.digest(['startup-metadata-review-v1'])
    for entry in inventory['entries']:
        assessment = file_status.resolve(entry['path'], entry.get('sha256'), proofs)
        # Construct only the observed startup fields. Never accept a target's
        # identity_verified or known_good_context claim, or borrow a process's
        # verdict for an unbound startup entry with merely the same hash/path.
        snapshot = {'executable': entry['path'], 'sha256': entry.get('sha256')}
        hit = known_good.lookup(s, snapshot, cfg['ai_model'], [policy],
                               bypass=assessment['status'] == 'changed')
        # The current metadata-only inventory cannot satisfy the strict cache
        # contract. A future richer collector must separately bind startup context.
        result['items'].append({'path': entry['path'], 'sha256': entry.get('sha256'),
            **assessment, 'known_good': {'status': 'bypassed' if assessment['status'] == 'changed' else 'miss',
                'reason': 'Authenticated artifact mismatch.' if assessment['status'] == 'changed' else
                          'Complete verified startup/process context is unavailable.',
                'reusable_for_startup': False},
            'behavior_status': 'unresolved'})
        if hit:
            raise ValueError('Unexpected known-good match without verified startup context')
    return result


def approve(s,host_id,inspection_id,evidence_digest,expected,reason,actor,review_digest=None):
    import uuid
    from .db import Setting,audit
    from .incidents import PersistenceBaseline
    current=review(s,host_id)
    if review_digest is not None and review_digest != current['review_digest']:
        raise ValueError('File provenance changed; refresh and review again')
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


# In-app notification for the startup-change incident lifecycle. Reasons are fixed
# text: endpoint-supplied paths, hashes and link targets never reach the bell.
NOTIFICATION_SOURCE='file-integrity'
NOTIFICATION_KIND='startup-change'
NOTIFICATION_SUBJECT='startup-incident'
CLOSED_STATES=('resolved','false_positive')
NOTIFICATION_REASONS={
    'opened':'A startup inspection on this server differs from the approved startup baseline. Review the changed startup entries; a change is not a malware verdict.',
    'reopened':'A previously closed startup change on this server was observed again. Review the changed startup entries; a change is not a malware verdict.',
    'review-reopened':'An administrator reopened a startup change on this server. Review the changed startup entries; a change is not a malware verdict.',
    'resolved':'This startup change was closed by administrator review.',
    'server-deleted':'The server was deleted; its startup change no longer needs attention here.',
}


def _notification_link(host_id):
    return '#servers/'+host_id+'/integrity'


def notify(s,row,change,revision):
    """Publish one durable, admin-only notification revision for a startup incident.

    Advisory only: it never acknowledges, transitions, approves plans, changes a
    baseline or remediates. Closing an incident that never published (legacy
    history) adds nothing. The caller owns the surrounding transaction.
    """
    from . import notifications
    closing=change=='resolved'
    if closing and not s.get(notifications.NotificationEvent,notifications._event_id(
            NOTIFICATION_SOURCE,NOTIFICATION_KIND,NOTIFICATION_SUBJECT,row.id,row.host_id)):return
    notifications.publish(s,source=NOTIFICATION_SOURCE,kind=NOTIFICATION_KIND,
        subject_type=NOTIFICATION_SUBJECT,subject_id=row.id,host_id=row.host_id,
        subject_revision=change+':'+revision,severity='info' if closing else 'medium',
        reason=NOTIFICATION_REASONS[change],deep_link=_notification_link(row.host_id),
        minimum_role='admin',lifecycle='resolved' if closing else 'active')


def notify_review(s,row,previous):
    """Notify review transitions across the closed boundary; acknowledgement is silent."""
    revision=repr(row.updated)
    if row.state in CLOSED_STATES and previous not in CLOSED_STATES:notify(s,row,'resolved',revision)
    elif row.state not in CLOSED_STATES and previous in CLOSED_STATES:notify(s,row,'review-reopened',revision)


def resolve_host_notifications(s,host_id):
    """Resolve still-active startup-change notifications for a deleted server."""
    from sqlalchemy import select
    from . import notifications
    N=notifications.NotificationEvent;R=notifications.NotificationRevision
    rows=s.execute(select(N.subject_id).join(R,(R.event_id==N.id)&(R.revision==N.revision)).where(
        N.source==NOTIFICATION_SOURCE,N.kind==NOTIFICATION_KIND,N.host_id==host_id,R.lifecycle=='active')).scalars().all()
    for incident_id in rows:
        notifications.publish(s,source=NOTIFICATION_SOURCE,kind=NOTIFICATION_KIND,
            subject_type=NOTIFICATION_SUBJECT,subject_id=incident_id,host_id=host_id,
            subject_revision='server-deleted',severity='info',reason=NOTIFICATION_REASONS['server-deleted'],
            deep_link=_notification_link(host_id),minimum_role='admin',lifecycle='resolved')


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
    previous=row.state if row else None
    if row:
        row.updated=max(time.time(),row.updated+.000001);row.state='open'
    else:
        row=PersistenceIncident(id=identifier,host_id=host_id,baseline_id=baseline_id,evidence={'changes':changes,'classification':'startup_change_not_malware_verdict'})
        s.add(row)
    # Repeat detections of an open/acknowledged incident are unchanged observations.
    if previous is None:notify(s,row,'opened',inspection_id)
    elif previous in CLOSED_STATES:notify(s,row,'reopened',inspection_id)
    s.add(PersistenceDetection(inspection_id=inspection_id,incident_id=identifier))
