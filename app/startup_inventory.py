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
    ('anacron','anacron table','/etc/anacrontab'),
    ('tcp_wrappers_allow','TCP wrappers allow rules','/etc/hosts.allow'),
    ('tcp_wrappers_deny','TCP wrappers deny rules','/etc/hosts.deny'),
    ('rsnapshot','rsnapshot configuration','/etc/rsnapshot.conf'),
    ('git_system','System git configuration','/etc/gitconfig'),
    ('kdump','kdump crash-capture configuration','/etc/kdump.conf'),
    ('request_key','keyutils request-key configuration','/etc/request-key.conf'),
    ('request_key_d','keyutils request-key drop-ins','/etc/request-key.d'),
)
GAPS=[
    'Cron jobs are parsed only from crontab-format files (/etc/crontab, /etc/cron.d and user spool crontabs) by agents that report them. Command redaction is best-effort and pattern-based, so unusual credential forms can remain; commands are bounded, standard input after an unescaped % is not stored, control characters are shown escaped, and environment values are not exported, and run-parts scripts (cron.daily and similar) are not parsed into jobs; anacron and at queue parsing is described separately below.',
    'Parsed jobs are data from the hashed file only: referenced scripts are not inspected. Each job shows the SHELL and PATH its crontab file assigns above it, as reported by agents that support it; cron daemon defaults, /etc/environment, PAM-supplied environment and how the shell resolves the command are not evaluated, and whether the cron daemon runs is not evaluated. /etc/crontab and /etc/cron.d files are checked against the distribution cron defaults for names, root ownership and permission bits from stored metadata; '+cron_loading.LIMITATION+' User spool crontab ownership/mode rules are not evaluated.',
    'Vendor/user systemd units, effective precedence, generated/transient units and runtime state are not enumerated.',
    '/var/spool/anacron timestamps, user login/autostart/SSH hooks, udev and module-load mechanisms are not comprehensively inventoried.',
    'Exception for anacron: /etc/anacrontab is hashed and its jobs are parsed into period, delay, job identifier and command from the hashed bytes by agents that report them, with the START_HOURS_RANGE and RANDOM_DELAY settings. Other environment values are counted, never stored; commands use the same best-effort redaction and are bounded to 64 jobs; lines anacron would reject are counted as unparsed. Scripts that run-parts commands execute, anacron timestamps and whether anacron runs (cron, systemd timer or boot) are not evaluated.',
    'TCP wrappers: /etc/hosts.allow and /etc/hosts.deny are hashed as startup files, and agents that report them parse their spawn, twist and aclexec commands from the hashed bytes with the libwrap 7.6.q (Debian patch set) rules: backslash continuations, the 2048-byte line limit, first-match order and option errors. Each command runs through /bin/sh -c as the daemon process user, often root, because the patched user and group options change no identity. A command after an entry that matches every daemon and client is shown as shadowed; weaker patterns are never treated as shadowing. Commands use the same best-effort redaction, are bounded to 64 per file and other option values are not stored. Whether any running daemon is linked against libwrap, which daemon and client names match a request, and what the commands do are not evaluated.',
    'rsnapshot: /etc/rsnapshot.conf is hashed as a startup file by agents that report it, but its cmd_preexec, cmd_postexec, backup_script, backup_exec, program-path and backtick include_conf commands are not yet parsed in this view. Files it includes, alternate configurations passed with -c and which cron entry or timer invokes rsnapshot are not evaluated.',
    'System git configuration: /etc/gitconfig is hashed as a startup file by agents that report it, but the shell aliases, pagers, editors, credential helpers, hook paths, fsmonitor hooks and diff, filter and merge drivers it can make git run are not yet parsed in this view. Files it includes, per-user, XDG and repository configuration, GIT_CONFIG_* environment overrides and which accounts or jobs run git are not evaluated.',
    'kdump: /etc/kdump.conf is hashed as a startup file by agents that report it, but its kdump_pre, kdump_post, kdump_emergency and core_collector commands are not yet parsed in this view. The /etc/kdump/pre.d, post.d and emergency.d directories, the hook programs themselves, whether the loaded crash-capture initramfs matches the current files, and the Debian kdump-tools configuration are not evaluated.',
    'keyutils request-key: /etc/request-key.conf and the /etc/request-key.d drop-in directory are hashed as startup files by agents that report them, but the rules that choose which program /sbin/request-key runs as root, with requester-chosen description and callout arguments, when the kernel asks for a missing key are not yet parsed in this view. The programs themselves, whether the kernel has key support and /sbin/request-key installed, and which processes request keys are not evaluated.',
    'Symlink targets are recorded, not followed. Custom scope does not imply individual jobs or referenced scripts were inspected.',
    'Package ownership/default authenticity and custom-versus-vendor origin are not assessed; no AI classification is made.',
    'Exception for at queues: Debian-family at job files in /var/spool/cron/atjobs are parsed into a queue, job number, scheduled time, owner and up to 32 command lines from the hashed bytes by agents that report them. Exported environment values are counted, never stored; commands use the same best-effort redaction; unrecognized layouts are shown as unparsed. Whether atd runs is not evaluated, and the RHEL-family /var/spool/at queue is outside built-in scope.',
]


def within(path,roots):
    return any(path==root or path.startswith(root+'/') for root in roots)


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


def anacron_state(entry):
    """Whether parsed anacron jobs exist, were not reported (older agent) or do not apply."""
    if 'anacron' in entry:return 'parsed'
    return 'not_reported' if entry['kind']=='regular' and entry['path']==persistence.ANACRONTAB else None


def anacron_text(entry):
    return ' '.join(j['identifier']+' '+j['command'] for j in entry.get('anacron',{}).get('jobs',()))


def tcp_wrappers_state(entry):
    """Whether parsed TCP wrappers commands exist, were not reported (older agent) or do not apply."""
    if 'tcp_wrappers' in entry:return 'parsed'
    return 'not_reported' if entry['kind']=='regular' and entry['path'] in persistence.TCP_WRAPPERS_FILES else None


def tcp_wrappers_view(entry,inventory):
    """Parsed commands with reachability: a match in hosts.allow returns before hosts.deny is read,
    unless an aclexec up to that entry can unmatch it; later entries in a file are never read."""
    parsed=dict(entry['tcp_wrappers']);allow=persistence.TCP_WRAPPERS_FILES[0];shadow=None;unknown=None
    if entry['path']!=allow:
        other=next((e for e in inventory['entries'] if e['path']==allow),None)
        if other is None:unknown=None if allow in inventory['missing_roots'] else 'hosts.allow was not collected in this inventory'
        elif other['kind']!='regular':unknown='hosts.allow is a symlink, which is recorded and not followed'
        elif 'tcp_wrappers' not in other:unknown='hosts.allow commands were not reported by this agent version'
        elif not other['tcp_wrappers']['parsed']:unknown='hosts.allow could not be parsed'
        elif other['tcp_wrappers']['unconditional_line'] is not None and not other['tcp_wrappers']['aclexec_through_unconditional']:
            shadow={'path':allow,'line':other['tcp_wrappers']['unconditional_line']}
    first=parsed['unconditional_line'];commands=[]
    for item in parsed['commands']:
        item=dict(item);local={'path':entry['path'],'line':first} if first is not None and item['line']>first else None
        by=local or shadow
        item.update(reachability='shadowed' if by else 'unknown' if unknown else 'reachable',shadowed_by=by)
        commands.append(item)
    parsed.update(commands=commands,reachability_unknown=unknown,
                  reachable=sum(c['reachability']=='reachable' for c in commands))
    return parsed


def tcp_wrappers_text(entry):
    return ' '.join(c['option']+' '+c['command']+' '+' '.join(c['daemons']) for c in entry.get('tcp_wrappers',{}).get('commands',()))


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
    """Mechanism counts; the at, anacron and TCP wrappers rows also report parsed jobs/commands and older-agent files."""
    result=[]
    for key,label,_ in CATALOG:
        if key=='anacron':
            states=[anacron_state(e) for e in inventory['entries']]
            jobs=sum(len(e['anacron']['jobs']) for e in inventory['entries'] if 'anacron' in e)
            label+=f' · {jobs} parsed job{"" if jobs==1 else "s"}'+(' · not reported by this agent version' if 'not_reported' in states else '')
        if key in ('tcp_wrappers_allow','tcp_wrappers_deny'):
            path=persistence.TCP_WRAPPERS_FILES[key=='tcp_wrappers_deny']
            found=[e for e in inventory['entries'] if e['path']==path]
            commands=sum(len(e['tcp_wrappers']['commands']) for e in found if 'tcp_wrappers' in e)
            label+=f' · {commands} parsed command{"" if commands==1 else "s"}'+(' · not reported by this agent version' if any(tcp_wrappers_state(e)=='not_reported' for e in found) else '')
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
    newly=assessment['comparison'].get('newly_in_scope',[]) if changes is not None else []
    earlier=assessment['comparison'].get('previously_custom',[]) if changes is not None else []
    for entry in inventory['entries']:
        key,label=mechanism(entry['path'])
        row={k:entry[k] for k in ('path','kind','uid','gid','mode','size','sha256','target') if k in entry}
        row.update(mechanism=key,mechanism_label=label,change=changes.get(entry['path'],'unchanged') if changes is not None else 'not_compared',origin='not_assessed',jobs_state=jobs_state(entry))
        if 'cron' in entry:row['cron']=entry['cron']
        state=anacron_state(entry)
        if state:row['anacron_state']=state
        if 'anacron' in entry:row['anacron']=entry['anacron']
        state=tcp_wrappers_state(entry)
        if state:row['tcp_wrappers_state']=state
        if 'tcp_wrappers' in entry:row['tcp_wrappers']=tcp_wrappers_view(entry,inventory)
        if entry['path'] in loading:row['cron_loading']=loading[entry['path']]
        jobs=' '.join(str(j['account'] or '')+' '+j['command'] for j in entry.get('cron',{}).get('jobs',()))
        # Built-in paths added after the baseline was collected were never compared, so they are not "unchanged".
        if changes is not None and within(entry['path'],newly) and not within(entry['path'],earlier):row['change']='not_in_baseline'
        if q.casefold() in (entry['path']+' '+label+' '+jobs+' '+anacron_text(entry)+' '+tcp_wrappers_text(entry)).casefold():rows.append(row)
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
        'missing_roots':inventory['missing_roots'],'newly_in_scope':newly,'skipped':inventory['skipped'],'gaps':GAPS+inventory['gaps'],
        'note':'Only files present in this bounded stored receipt. Missing files/mechanisms are not proof of absence or safety; removed files remain in baseline differences.'}
