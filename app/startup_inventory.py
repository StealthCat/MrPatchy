"""Read-only review of bounded stored startup metadata, never job/default attestation."""
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
)
GAPS=[
    'Stored file metadata only: cron jobs, schedules, accounts and effective commands are not parsed.',
    'Vendor/user systemd units, effective precedence, generated/transient units and runtime state are not enumerated.',
    'Anacron/at queues, user login/autostart/SSH hooks, udev and module-load mechanisms are not comprehensively inventoried.',
    'Symlink targets are recorded, not followed. Custom scope does not imply individual jobs or referenced scripts were inspected.',
    'Package ownership/default authenticity and custom-versus-vendor origin are not assessed; no AI classification is made.',
]


def mechanism(path):
    for key,label,prefix in CATALOG:
        if path==prefix or path.startswith(prefix+'/') or (prefix=='/etc/cron' and (path.startswith('/etc/cron.') or path=='/etc/crontab')):
            return key,label
    return 'additional','Additional inventory scope'


def page(s,host_id,offset=0,q='',expected_digest=''):
    assessment=persistence.status(s,host_id);latest=assessment['latest']
    if latest is None and expected_digest:raise ValueError('Startup inventory changed; reopen the browser')
    if latest is None:return {'state':'unavailable','items':[],'more':False,'total':0,'digest':'','catalog':[], 'gaps':GAPS,'scope':[],'inspection_id':None,'created':None,'baseline_state':assessment['state']}
    inventory=latest['inventory'];persistence.validate(inventory)
    revision=digest({'inspection':latest['id'],'inventory':inventory,'baseline':assessment['baseline']})
    if expected_digest and expected_digest!=revision:raise ValueError('Startup inventory or baseline changed; reopen the browser')
    changes={r['path']:r['kind'] for r in assessment['comparison']['changes']} if assessment['comparison']['state']=='compared' else None
    rows=[]
    for entry in inventory['entries']:
        key,label=mechanism(entry['path'])
        row={k:entry[k] for k in ('path','kind','uid','gid','mode','size','sha256','target') if k in entry}
        row.update(mechanism=key,mechanism_label=label,change=changes.get(entry['path'],'unchanged') if changes is not None else 'not_compared',origin='not_assessed')
        if q.casefold() in (entry['path']+' '+label).casefold():rows.append(row)
    rows.sort(key=lambda r:r['path'])
    catalog=[{'id':key,'label':label,'observed_files':sum(mechanism(e['path'])[0]==key for e in inventory['entries'])} for key,label,_ in CATALOG]
    return {'state':inventory['state'],'items':rows[offset:offset+25],'more':len(rows)>offset+25,'total':len(rows),'digest':revision,
        'inspection_id':latest['id'],'created':latest['created'],'baseline_state':assessment['state'],'catalog':catalog,'scope':inventory['scope'],
        'missing_roots':inventory['missing_roots'],'skipped':inventory['skipped'],'gaps':GAPS+inventory['gaps'],
        'note':'Only files present in this bounded stored receipt. Missing files/mechanisms are not proof of absence or safety; removed files remain in baseline differences.'}
