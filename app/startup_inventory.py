"""Read-only review of bounded stored startup metadata and parsed cron jobs, never job/default attestation."""
from . import persistence
from .incidents import digest

CATALOG=(
    ('systemd_local','Local systemd definitions','/etc/systemd/system'),
    ('cron','System cron definitions','/etc/cron'),
    ('cron_spool','User/root cron spool files','/var/spool/cron'),
    ('sysv','SysV init scripts','/etc/init.d'),
    ('shell','System profile snippets','/etc/profile.d'),
    ('boot','Local boot script','/etc/rc.local'),
    ('loader','Loader preload configuration','/etc/ld.so.preload'),
    ('anacron','anacron table','/etc/anacrontab'),
)
GAPS=[
    'Cron jobs are parsed only from crontab-format files (/etc/crontab, /etc/cron.d and user spool crontabs) by agents that report them. Command redaction is best-effort and pattern-based, so unusual credential forms can remain; commands are bounded, standard input after an unescaped % is not stored, control characters are shown escaped, and environment values are not exported, and run-parts scripts (cron.daily and similar), anacron and at queues are not parsed into jobs.',
    'Parsed jobs are data from the hashed file only: referenced scripts are not inspected, and cron.d naming rules, PATH/SHELL settings and whether the cron daemon runs are not evaluated.',
    'Vendor/user systemd units, effective precedence, generated/transient units and runtime state are not enumerated.',
    '/etc/anacrontab is hashed as a startup file by agents that report it, but its jobs are not parsed; /var/spool/anacron timestamps and at queues, user login/autostart/SSH hooks, udev and module-load mechanisms are not comprehensively inventoried.',
    'Symlink targets are recorded, not followed. Custom scope does not imply individual jobs or referenced scripts were inspected.',
    'Package ownership/default authenticity and custom-versus-vendor origin are not assessed; no AI classification is made.',
]


def mechanism(path):
    for key,label,prefix in CATALOG:
        if path==prefix or path.startswith(prefix+'/') or (prefix=='/etc/cron' and (path.startswith('/etc/cron.') or path=='/etc/crontab')):
            return key,label
    return 'additional','Additional inventory scope'


CRON_FILES=('/etc/crontab',)
CRON_DIRS=('/etc/cron.d','/var/spool/cron/crontabs','/var/spool/cron')


def jobs_state(entry):
    """Whether parsed jobs exist, were not reported (older agent) or do not apply."""
    if 'cron' in entry:return 'parsed'
    path=entry['path'];parent=path.rsplit('/',1)[0]
    return 'not_reported' if entry['kind']=='regular' and (path in CRON_FILES or parent in CRON_DIRS) else 'not_crontab'


def page(s,host_id,offset=0,q='',expected_digest=''):
    assessment=persistence.status(s,host_id);latest=assessment['latest']
    if latest is None and expected_digest:raise ValueError('Startup inventory changed; reopen the browser')
    if latest is None:return {'state':'unavailable','items':[],'more':False,'total':0,'digest':'','catalog':[], 'gaps':GAPS,'scope':[],'inspection_id':None,'created':None,'baseline_state':assessment['state']}
    inventory=latest['inventory'];persistence.validate(inventory)
    revision=digest({'inspection':latest['id'],'inventory':inventory,'baseline':assessment['baseline']})
    if expected_digest and expected_digest!=revision:raise ValueError('Startup inventory or baseline changed; reopen the browser')
    changes={r['path']:r['kind'] for r in assessment['comparison']['changes']} if assessment['comparison']['state']=='compared' else None
    rows=[]
    newly=assessment['comparison'].get('newly_in_scope',[]) if changes is not None else []
    for entry in inventory['entries']:
        key,label=mechanism(entry['path'])
        row={k:entry[k] for k in ('path','kind','uid','gid','mode','size','sha256','target') if k in entry}
        row.update(mechanism=key,mechanism_label=label,change=changes.get(entry['path'],'unchanged') if changes is not None else 'not_compared',origin='not_assessed',jobs_state=jobs_state(entry))
        if 'cron' in entry:row['cron']=entry['cron']
        jobs=' '.join(str(j['account'] or '')+' '+j['command'] for j in entry.get('cron',{}).get('jobs',()))
        # Built-in paths added after the baseline was collected were never compared, so they are not "unchanged".
        if changes is not None and any(entry['path']==root or entry['path'].startswith(root+'/') for root in newly):row['change']='not_in_baseline'
        if q.casefold() in (entry['path']+' '+label+' '+jobs).casefold():rows.append(row)
    rows.sort(key=lambda r:r['path'])
    catalog=[{'id':key,'label':label,'observed_files':sum(mechanism(e['path'])[0]==key for e in inventory['entries'])} for key,label,_ in CATALOG]
    parsed=[e for e in inventory['entries'] if 'cron' in e]
    cron={'files':len(parsed),'jobs':sum(len(e['cron']['jobs']) for e in parsed),'unparsed':sum(e['cron']['unparsed'] for e in parsed),
          'truncated':any(e['cron']['truncated'] for e in parsed),'not_reported':sum(jobs_state(e)=='not_reported' for e in inventory['entries'])}
    return {'state':inventory['state'],'items':rows[offset:offset+25],'cron':cron,'more':len(rows)>offset+25,'total':len(rows),'digest':revision,
        'inspection_id':latest['id'],'created':latest['created'],'baseline_state':assessment['state'],'catalog':catalog,'scope':inventory['scope'],
        'missing_roots':inventory['missing_roots'],'newly_in_scope':newly,'skipped':inventory['skipped'],'gaps':GAPS+inventory['gaps'],
        'note':'Only files present in this bounded stored receipt. Missing files/mechanisms are not proof of absence or safety; removed files remain in baseline differences.'}
