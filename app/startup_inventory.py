"""Read-only review of bounded stored startup metadata and parsed cron jobs, never job/default attestation."""
from . import cron_loading, persistence
from .db import Host
from .incidents import digest
import re

CATALOG=(
    ('systemd_local','Local systemd definitions','/etc/systemd/system'),
    ('cron','System cron definitions','/etc/cron'),
    ('at','Debian-family at job queue',persistence.AT_SPOOL_DIR),
    ('cron_spool','User/root cron spool files','/var/spool/cron'),
    ('sysv','SysV init scripts','/etc/init.d'),
    ('shell','System profile snippets','/etc/profile.d'),
    ('boot','Local boot script','/etc/rc.local'),
    ('loader','Loader preload configuration','/etc/ld.so.preload'),
)
GAPS=[
    'Cron jobs are parsed only from crontab-format files (/etc/crontab, /etc/cron.d and user spool crontabs) by agents that report them. Command redaction is best-effort and pattern-based, so unusual credential forms can remain; commands are bounded, standard input after an unescaped % is not stored, control characters are shown escaped, and environment values are not exported, and run-parts scripts (cron.daily and similar), anacron and at queues are not parsed into jobs.',
    'Parsed jobs are data from the hashed file only: referenced scripts are not inspected, and PATH/SHELL settings and whether the cron daemon runs are not evaluated. /etc/crontab and /etc/cron.d files are checked against the distribution cron defaults for names, root ownership and permission bits from stored metadata; '+cron_loading.LIMITATION+' User spool crontab ownership/mode rules are not evaluated.',
    'Vendor/user systemd units, effective precedence, generated/transient units and runtime state are not enumerated.',
    'Anacron/at queues, user login/autostart/SSH hooks, udev and module-load mechanisms are not comprehensively inventoried.',
    'Symlink targets are recorded, not followed. Custom scope does not imply individual jobs or referenced scripts were inspected.',
    'Package ownership/default authenticity and custom-versus-vendor origin are not assessed; no AI classification is made.',
    'Exception for at queues: Debian-family at job files in /var/spool/cron/atjobs are parsed into a queue, job number, scheduled time, owner and up to 32 command lines from the hashed bytes by agents that report them. Exported environment values are counted, never stored; commands use the same best-effort redaction; unrecognized layouts are shown as unparsed. Whether atd runs is not evaluated, and the RHEL-family /var/spool/at queue is outside built-in scope.',
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


def at_state(entry):
    """Whether a parsed at job exists, was not reported (older agent) or does not apply."""
    if 'at' in entry:return 'parsed'
    path=entry['path'];name=path.rsplit('/',1)
    return 'not_reported' if entry['kind']=='regular' and name[0]==persistence.AT_SPOOL_DIR and re.fullmatch(r'[a-zA-Z=][0-9a-f]{13}',name[1]) else None


def with_at_jobs(rows,inventory,q,changes):
    """Attach parsed at jobs to matching rows and add entries found only by an at account or command."""
    by_path={r['path']:r for r in rows}
    for entry in inventory['entries']:
        state=at_state(entry)
        if state is None:continue
        row=by_path.get(entry['path'])
        if row is None:
            at=entry.get('at') or {}
            text=' '.join([at.get('account') or '']+list(at.get('commands',())))
            if not q or q.casefold() not in text.casefold():continue
            key,label=mechanism(entry['path'])
            row={k:entry[k] for k in ('path','kind','uid','gid','mode','size','sha256','target') if k in entry}
            row.update(mechanism=key,mechanism_label=label,change=changes.get(entry['path'],'unchanged') if changes is not None else 'not_compared',origin='not_assessed',jobs_state=jobs_state(entry))
            rows.append(row)
        row['at_state']=state
        if 'at' in entry:row['at']=entry['at']
    rows.sort(key=lambda r:r['path'])
    return rows


def catalog_rows(inventory):
    """Mechanism counts; the at row also reports parsed and older-agent job files."""
    result=[]
    for key,label,_ in CATALOG:
        if key=='at':
            states=[at_state(e) for e in inventory['entries']]
            parsed=states.count('parsed');missing=states.count('not_reported')
            label+=f' · {parsed} parsed job{"" if parsed==1 else "s"}'+(f' · {missing} not reported by this agent version' if missing else '')
        result.append({'id':key,'label':label,'observed_files':sum(mechanism(e['path'])[0]==key for e in inventory['entries'])})
    return result


def page(s,host_id,offset=0,q='',expected_digest=''):
    assessment=persistence.status(s,host_id);latest=assessment['latest']
    if latest is None and expected_digest:raise ValueError('Startup inventory changed; reopen the browser')
    if latest is None:return {'state':'unavailable','items':[],'more':False,'total':0,'digest':'','catalog':[], 'gaps':GAPS,'scope':[],'inspection_id':None,'created':None,'baseline_state':assessment['state']}
    inventory=latest['inventory'];persistence.validate(inventory)
    revision=digest({'inspection':latest['id'],'inventory':inventory,'baseline':assessment['baseline']})
    if expected_digest and expected_digest!=revision:raise ValueError('Startup inventory or baseline changed; reopen the browser')
    changes={r['path']:r['kind'] for r in assessment['comparison']['changes']} if assessment['comparison']['state']=='compared' else None
    host=s.get(Host,host_id);family=cron_loading.family_of(host.inventory if host else None)
    loading={e['path']:cron_loading.assess(e,family) for e in inventory['entries'] if cron_loading.applies(e['path'])}
    rows=[]
    for entry in inventory['entries']:
        key,label=mechanism(entry['path'])
        row={k:entry[k] for k in ('path','kind','uid','gid','mode','size','sha256','target') if k in entry}
        row.update(mechanism=key,mechanism_label=label,change=changes.get(entry['path'],'unchanged') if changes is not None else 'not_compared',origin='not_assessed',jobs_state=jobs_state(entry))
        if 'cron' in entry:row['cron']=entry['cron']
        if entry['path'] in loading:row['cron_loading']=loading[entry['path']]
        jobs=' '.join(str(j['account'] or '')+' '+j['command'] for j in entry.get('cron',{}).get('jobs',()))
        if q.casefold() in (entry['path']+' '+label+' '+jobs).casefold():rows.append(row)
    rows.sort(key=lambda r:r['path'])
    rows=with_at_jobs(rows,inventory,q,changes)
    catalog=catalog_rows(inventory)
    parsed=[e for e in inventory['entries'] if 'cron' in e]
    cron={'files':len(parsed),'jobs':sum(len(e['cron']['jobs']) for e in parsed),'unparsed':sum(e['cron']['unparsed'] for e in parsed),
          'truncated':any(e['cron']['truncated'] for e in parsed),'not_reported':sum(jobs_state(e)=='not_reported' for e in inventory['entries']),
          'skipped_files':sum(r['state']=='skipped' for r in loading.values()),'unknown_loading':sum(r['state']=='unknown' for r in loading.values()),
          'loading_family':family,'loading_limitation':cron_loading.LIMITATION}
    return {'state':inventory['state'],'items':rows[offset:offset+25],'cron':cron,'more':len(rows)>offset+25,'total':len(rows),'digest':revision,
        'inspection_id':latest['id'],'created':latest['created'],'baseline_state':assessment['state'],'catalog':catalog,'scope':inventory['scope'],
        'missing_roots':inventory['missing_roots'],'skipped':inventory['skipped'],'gaps':GAPS+inventory['gaps'],
        'note':'Only files present in this bounded stored receipt. Missing files/mechanisms are not proof of absence or safety; removed files remain in baseline differences.'}
