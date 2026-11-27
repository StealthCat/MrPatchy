"""Read-only review of bounded stored startup metadata and parsed cron jobs, never job/default attestation."""
from . import autofs_program_maps, clamav_event_commands, cron_loading, dovecot_services, persistence
from .db import Host
from .incidents import digest
import fnmatch
import posixpath
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
    ('autofs','autofs master map','/etc/auto.master'),
    ('request_key','keyutils request-key configuration','/etc/request-key.conf'),
    ('request_key_d','keyutils request-key drop-ins','/etc/request-key.d'),
    ('clamav','ClamAV configuration','/etc/clamav'),
    ('clamav_clamd_d','ClamAV clamd configuration','/etc/clamd.d'),
    ('clamav_freshclam','ClamAV freshclam configuration','/etc/freshclam.conf'),
    ('dovecot','Dovecot configuration','/etc/dovecot'),
    ('strongswan','strongSwan swanctl configuration','/etc/swanctl'),
    ('strongswan_rpm','strongSwan configuration','/etc/strongswan'),
    ('runit','runit service directory','/etc/service'),
    ('runit_stages','runit stages and run levels','/etc/runit'),
    ('runit_sv','runit service definitions','/etc/sv'),
    ('lvm','LVM configuration','/etc/lvm/lvm.conf'),
    ('lvm_local','LVM local configuration','/etc/lvm/lvmlocal.conf'),
)
GAPS=[
    'Cron jobs are parsed only from crontab-format files (/etc/crontab, /etc/cron.d and user spool crontabs) by agents that report them. Command redaction is best-effort and pattern-based, so unusual credential forms can remain; commands are bounded, standard input after an unescaped % is not stored, control characters are shown escaped, and environment values are not exported, and run-parts scripts (cron.daily and similar) are not parsed into jobs; anacron and at queue parsing is described separately below.',
    'Parsed jobs are data from the hashed file only: referenced scripts are not inspected. Each job shows the SHELL and PATH its crontab file assigns above it, as reported by agents that support it; cron daemon defaults, /etc/environment, PAM-supplied environment and how the shell resolves the command are not evaluated, and whether the cron daemon runs is not evaluated. /etc/crontab and /etc/cron.d files are checked against the distribution cron defaults for names, root ownership and permission bits from stored metadata; '+cron_loading.LIMITATION+' User spool crontab ownership/mode rules are not evaluated.',
    'Vendor/user systemd units, effective precedence, generated/transient units and runtime state are not enumerated.',
    '/var/spool/anacron timestamps, user login/autostart/SSH hooks, udev and module-load mechanisms are not comprehensively inventoried.',
    'Exception for anacron: /etc/anacrontab is hashed and its jobs are parsed into period, delay, job identifier and command from the hashed bytes by agents that report them, with the START_HOURS_RANGE and RANDOM_DELAY settings. Other environment values are counted, never stored; commands use the same best-effort redaction and are bounded to 64 jobs; lines anacron would reject are counted as unparsed. Scripts that run-parts commands execute, anacron timestamps and whether anacron runs (cron, systemd timer or boot) are not evaluated.',
    'TCP wrappers: /etc/hosts.allow and /etc/hosts.deny are hashed as startup files, and agents that report them parse their spawn, twist and aclexec commands from the hashed bytes with the libwrap 7.6.q (Debian patch set) rules: backslash continuations, the 2048-byte line limit, first-match order and option errors. Each command runs through /bin/sh -c as the daemon process user, often root, because the patched user and group options change no identity. A command after an entry that matches every daemon and client is shown as shadowed; weaker patterns are never treated as shadowing. Commands use the same best-effort redaction, are bounded to 64 per file and other option values are not stored. Whether any running daemon is linked against libwrap, which daemon and client names match a request, and what the commands do are not evaluated.',
    'rsnapshot: /etc/rsnapshot.conf is hashed as a startup file by agents that report it, but its cmd_preexec, cmd_postexec, backup_script, backup_exec, program-path and backtick include_conf commands are not yet parsed in this view. Files it includes, alternate configurations passed with -c and which cron entry or timer invokes rsnapshot are not evaluated.',
    'autofs: /etc/auto.master is hashed as a startup file, and agents that report it also send its text (up to 64 KiB). This view lists its entries (mount point and map) with the autofs 5.1.9 master-map rules, but the agent never looks up the map paths they name, because a lookup at or below an automount point can mount a map or run a program map. Which maps are program maps that automount runs as root on each key lookup is therefore not resolved, and every entry stays unknown. Also not evaluated: the map files and their + includes and sub-maps, the /etc/auto.master.d directory, master-map + includes, the /etc/auto_master fallback, an alternate master map set in autofs.conf or on the command line, autofs.conf amd sections, nsswitch automount sources, remote (LDAP, NIS, SSS) maps and whether automount runs. The result is never complete.',
    'System git configuration: /etc/gitconfig is hashed as a startup file by agents that report it, but the shell aliases, pagers, editors, credential helpers, hook paths, fsmonitor hooks and diff, filter and merge drivers it can make git run are not yet parsed in this view. Files it includes, per-user, XDG and repository configuration, GIT_CONFIG_* environment overrides and which accounts or jobs run git are not evaluated.',
    'kdump: /etc/kdump.conf is hashed as a startup file, and agents that report it parse its kdump_pre, kdump_post and kdump_emergency programs and core_collector argv from the hashed bytes with the kdump-utils 7bf4714 rules, in capture order. Each runs as root in the crash-capture environment after a kernel crash. Options kdumpctl rejects (unknown, deprecated, empty, repeated, a second dump target or a second --mount) are listed with their line, and such a configuration loads no capture kernel, so nothing runs. Programs use the same best-effort redaction, other option values are never stored, and text over 64 KiB, with 2048 or more lines, not UTF-8 or with NUL bytes is shown as unparsed. The /etc/kdump/pre.d, post.d and emergency.d directories are not yet listed, so their programs are missing from the sequence. The hook programs themselves, other kdumpctl checks, whether the loaded crash-capture initramfs matches the current files and the Debian kdump-tools configuration are not evaluated.',
    'keyutils request-key: /etc/request-key.conf and the /etc/request-key.d drop-in directory are hashed as startup files, and agents that report them parse each file /sbin/request-key reads (drop-ins named *.conf, not starting with a dot, that are regular files) from the hashed bytes with the keyutils 1.6.3 rules. Each rule shows its operation, key type, description and callout patterns, whether the kernel upcall (create) reaches it, the pipe mode and the command it runs as root, with requester-controlled inputs (%d, %c, %{type:description} and piped callout information) named. Lines that abort lookups (4096 bytes or more, or ending before the program) are listed with the patterns a request must match first; one that matches every kernel lookup in any read file makes every lookup abort. Commands use the same best-effort redaction, patterns are bounded to 256 characters, rules and aborts to 64 per file, and text over 64 KiB, not UTF-8 or with NUL bytes is shown as unparsed. The readdir() order of drop-ins is not captured, so which of two equally specific rules in different files wins is not shown. The programs themselves, which key types an unprivileged requester may ask for, whether the kernel has key support and /sbin/request-key installed, and which processes request keys are not evaluated.',
    'ClamAV: the Debian-family /etc/clamav directory (clamd.conf, freshclam.conf and the onupdateexecute.d and onerrorexecute.d directories), the RPM-family /etc/clamd.d directory and /etc/freshclam.conf are hashed as startup files, and agents that report them parse /etc/clamav/clamd.conf and /etc/clamav/freshclam.conf from the hashed bytes with the ClamAV 1.5.4 option-parser rules. This view shows the VirusEvent command clamd runs through /bin/sh on every detection, waiting under a lock shared by every scan, and the OnUpdateExecute, OnErrorExecute and OnOutdatedExecute commands freshclam runs through system(), with their line and account. A file the parser rejects (unknown option, Example line, bad value or quoting) loads nothing, and its reason and line are shown. Commands use the same best-effort redaction and are bounded to 512 characters; the User, DatabaseOwner and daemon values are kept and every other value, including proxy passwords, is dropped. Accounts assume clamd and freshclam start as root, as the packaged units do. Whether freshclam runs in daemon mode is not observed, so which text OnOutdatedExecute runs and whether an EXIT_<n> command exits instead of running are shown as conditional. The RPM-family files are hashed but not yet parsed. Options given on the command line, alternate files passed with --config-file, the onupdateexecute.d and onerrorexecute.d scripts, whether either daemon runs, and the commands themselves are not evaluated.',
    'Dovecot: the /etc/dovecot directory (dovecot.conf, conf.d and any other files it holds, including passdb/userdb and key files, as metadata and SHA-256 only) is hashed as startup files by agents that report it, and agents that report parsed statements let this view evaluate the non-default service executables the root master process execs from dovecot.conf, as root unless drop_priv_before_exec is set. Only section headers, include patterns and the service and global settings the evaluation reads are stored; every other value is dropped. Included files outside /etc/dovecot (such as /usr/share/dovecot/protocols.d) and symlinked files are not observed, so an evaluation that reaches them stops with a blocking gap. /etc/passwd and /etc/group are not captured, so accounts are shown by name only. Configuration passed with -c, whether dovecot runs, the programs themselves, checkpassword passdb/userdb programs, quota_warning and sieve extprograms are not evaluated.',
    'strongSwan: the Debian-family /etc/swanctl directory (swanctl.conf, conf.d and the x509, private and other credential directories, as metadata and SHA-256 only) and the RPM-family /etc/strongswan directory (swanctl/, strongswan.conf and strongswan.d) are hashed as startup files by agents that report them, but the updown command charon runs as root through /bin/sh for each connection child on CHILD_SA up and down is not yet parsed in this view. The Debian-family /etc/strongswan.conf and /etc/strongswan.d (which can disable the updown plugin), legacy ipsec.conf leftupdown and leftfirewall, configuration passed with swanctl --file, connections loaded over vici by other clients, whether charon runs and the commands themselves are not evaluated.',
    'runit: /etc/service (on Debian and Ubuntu a symlink to runit/runsvdir/current, recorded, not followed), the /etc/runit directory (the 1, 2 and 3 stage scripts, ctrlaltdel and the runsvdir run-level directories of service links) and the /etc/sv service definitions (run, finish, log/run, down and control files) are hashed as startup files, as metadata and SHA-256 only, by agents that report them. Which programs runsvdir makes runsv run, on which event and as which account is not yet evaluated in this view. Service directories outside these paths (such as /usr/share/runit/sv or a runsvdir started with another directory), the supervise state under /run/runit, the contents of run scripts (including any chpst privilege drop), whether runsvdir runs and the programs themselves are not evaluated.',
    'LVM2: /etc/lvm/lvm.conf and /etc/lvm/lvmlocal.conf are hashed as startup files, as metadata and SHA-256 only, by agents that report them, but which thin/cache check, dump and repair executables, vdoformat and fsadm programs lvm commands run as root, the lvmlockctl kill command, and the dmeventd executable, plugin libraries and thin/vdo commands the configuration names are not yet evaluated in this view. Host-tag files (/etc/lvm/lvm_<tag>.conf), profiles, the archive, backup, cache and devices directories, configuration passed with --config or LVM_SYSTEM_DIR, copies in the initramfs, whether dmeventd runs and the programs themselves are not observed or evaluated. A custom /etc/lvm path saved earlier keeps its own scope and leaves the two files to built-in scope.',
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


def kdump_state(entry):
    """Whether parsed kdump hooks exist, were not reported (older agent) or do not apply."""
    if 'kdump' in entry:return 'parsed'
    return 'not_reported' if entry['kind']=='regular' and entry['path']==persistence.KDUMP_CONF else None


def kdump_text(entry):
    kdump=entry.get('kdump',{})
    return ' '.join([h['source']+' '+h['program']+' '+' '.join(h['args']) for h in kdump.get('hooks',())]+[r['option'] for r in kdump.get('refusals',())])


def request_key_state(entry):
    """Whether parsed request-key rules exist, were not reported (older agent), or request-key skips the file."""
    if 'request_key' in entry:return 'parsed'
    path=entry['path']
    if persistence.request_key_reads(path):
        if entry['kind']=='regular':return 'not_reported'
        # request-key opens request-key.conf with fopen(), which follows a symlink the inventory does not.
        return 'skipped_kind' if path!=persistence.REQUEST_KEY_CONF else 'not_followed'
    if path.startswith(persistence.REQUEST_KEY_DIR+'/'):
        return 'skipped_subdirectory' if '/' in path[len(persistence.REQUEST_KEY_DIR)+1:] else 'skipped_name'
    return None


def request_key_lookups(inventory):
    """Lines in any read file that make every kernel lookup abort, and whether every read file was parsed."""
    aborts=[];complete=True
    for entry in inventory['entries']:
        state=request_key_state(entry)
        if state in ('not_reported','not_followed') or (state=='parsed' and not entry['request_key']['parsed']):complete=False
        if state=='parsed' and entry['request_key']['universal_abort_line'] is not None:
            aborts.append(f"{entry['path']}:{entry['request_key']['universal_abort_line']}")
    return {'universal_aborts':sorted(aborts),'complete':complete}


def request_key_text(entry):
    report=entry.get('request_key',{})
    return ' '.join(' '.join((r['op'],r['type'],r['description'],r['callout_info'],r['command'])) for r in report.get('rules',()))


def tcp_wrappers_text(entry):
    return ' '.join(c['option']+' '+c['command']+' '+' '.join(c['daemons']) for c in entry.get('tcp_wrappers',{}).get('commands',()))


AUTOFS_CAPTURE_GAPS=(
    {'code':'map_paths_not_observed','detail':'The agent never looks up map paths, because a lookup at or below an automount point can mount a map or run a program map; whether each named map is a program, a text map or missing is unknown.','blocking':True},
    {'code':'nsswitch_not_observed','detail':'The automount: sources in /etc/nsswitch.conf were not captured; files is assumed, and other sources can add maps.','blocking':True},
    {'code':'autofs_conf_not_observed','detail':'autofs.conf was not captured; master_map_name could select a different master map.','blocking':True},
)


def autofs_state(entry):
    """Whether master-map entries were reported, refused, not reported (older agent) or do not apply."""
    if 'autofs' in entry:return 'resolved' if entry['autofs']['error'] is None else entry['autofs']['error']
    return 'not_reported' if entry['kind']=='regular' and entry['path']==persistence.AUTOFS_MASTER else None


def autofs_view(entry):
    """Master-map entries from the reported text. No map path is observed, so none resolves to a program; never a safety verdict."""
    data=entry['autofs']
    # Only the master map itself is observed (its stat is the hashed row). Every other path is unobserved.
    stats={persistence.AUTOFS_MASTER:{'kind':'regular','mode':entry['mode']}}
    result=autofs_program_maps.evaluate_master(files={persistence.AUTOFS_MASTER:data['text']},stats=stats)
    gaps=[dict(g) for g in AUTOFS_CAPTURE_GAPS]
    gaps+=result['gaps']
    entries=[{k:e.get(k) for k in ('mount_point','type','format','map','resolved','path')} for e in result['entries']]
    return {'programs':[{k:p[k] for k in ('path','argv','user','cwd','trigger')} for p in result['programs']],
            'entries':entries,'gaps':[{'code':g['code'],'detail':g['detail'],'blocking':bool(g.get('blocking')),
            **{k:str(g[k])[:200] for k in ('path','mount_point','source') if g.get(k) is not None}} for g in gaps[:autofs_program_maps.MAX_GAPS]],
            'complete':False,'origin':'not_assessed','authorizes_response':False,'contract_version':result['contract_version']}


def autofs_text(entry):
    if 'autofs' not in entry or entry['autofs']['error'] is not None:return ''
    view=autofs_view(entry)
    return ' '.join(p['path'] for p in view['programs'])+' '+' '.join((e['mount_point'] or '')+' '+(e['map'] or '')+' '+(e['path'] or '') for e in view['entries'])


def clamav_state(entry):
    """Whether parsed ClamAV options exist, were not reported (older agent), the symlink is not followed, or the RPM file is not parsed."""
    if 'clamav' in entry:return 'parsed'
    path=entry['path']
    if path in persistence.CLAMAV_FILES:return 'not_reported' if entry['kind']=='regular' else 'not_followed'
    if entry['kind']=='regular' and (path=='/etc/freshclam.conf' or (path.startswith('/etc/clamd.d/') and path.endswith('.conf'))):return 'not_parsed_family'
    return None


def clamav_view(entry):
    """The commands clamd or freshclam runs, rebuilt by the contract from the agent's parsed values.

    Accounts assume the daemon starts as root, as the packaged units do; freshclam daemon mode is not
    observed. Never a safety verdict and never authorizes a response."""
    report=entry['clamav'];tool=persistence.CLAMAV_FILES[entry['path']]
    view={'tool':tool,'parsed':report['parsed'],'accepted':report['accepted'],'error':report['error'],'redacted':report['redacted'],
          'commands':[],'daemon_line':None,'origin':'not_assessed','authorizes_response':False,
          'contract_version':clamav_event_commands.CONTRACT_VERSION}
    if not report['parsed']:return view
    values=report['values'];by_line={v['line']:v for v in values.values()}
    if 'daemon' in values:view['daemon_line']=values['daemon']['line']
    plain={n:{'value':v['value'],'line':v['line']} for n,v in values.items()}
    rows=clamav_event_commands.commands_from_values(tool,report['accepted'],plain,entry['path'],started_as_root=True,freshclam_daemon=None)
    # Outside daemon mode freshclam applies its own substitutions (OnOutdatedExecute loses its first %v)
    # before EXIT_<n> is read, so the conditional exit comes from the contract's foreground result.
    foreground={r['directive']:r['exit_status_instead'] for r in clamav_event_commands.commands_from_values(
        tool,report['accepted'],plain,entry['path'],started_as_root=True,freshclam_daemon=False)} if tool=='freshclam' else {}
    for row in rows:
        source=by_line[row['line']]
        view['commands'].append({'directive':row['directive'],'line':row['line'],'trigger':row['trigger'],'runs':row['runs'],
            'command':row['configured'],'truncated':source['truncated'],'redacted':source['redacted'],'argv':row['argv'],
            'account':{k:row['account'][k] for k in ('name','source','line') if k in row['account']},
            'waits':row['waits'] if tool=='clamd' else None,'substitutions':row['substitutions'],
            'command_source':row.get('command_source'),
            'exit_status_outside_daemon':foreground.get(row['directive'])})
    return view


def clamav_text(entry):
    if 'clamav' not in entry:return ''
    return ' '.join(c['directive']+' '+c['command']+' '+(c['account']['name'] or '') for c in clamav_view(entry)['commands'])


def _dovecot_quote(value):
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def dovecot_text(report):
    """Rebuild configuration text the contract reads identically: each statement on its own line number."""
    lines={}
    for item in report['statements']:
        op=item['op']
        if op=='include':text=('!include_try ' if item['optional'] else '!include ')+_dovecot_quote(item['pattern'])
        elif op=='close':text='}'
        elif op=='open':text=item['kind']+(' '+_dovecot_quote(item['name']) if item['name'] is not None else '')+' {'
        elif op=='set':text=item['key']+' = '+('<not_captured' if item['file'] else _dovecot_quote(item['value'] or ''))
        else:text='{'
        lines[item['line']]=text
    return '\n'.join(lines.get(n,'') for n in range(1,max(lines,default=0)+1))+'\n'


def dovecot_state(entry):
    """Whether Dovecot statements were reported, refused or not reported (older agent) for this file."""
    if 'dovecot' in entry:return 'parsed' if entry['dovecot']['parsed'] else 'unparsed'
    return 'not_reported' if entry['kind']=='regular' and entry['path'].startswith(persistence.DOVECOT_DIR+'/') else None


def dovecot_view(inventory):
    """Evaluate app/dovecot_services over the reported statements. Unreported, unparsed, truncated and
    symlinked files stay unobserved; absent paths and glob matches are observed only when the stored
    inventory is a complete collection. passwd/group are not captured. Never a safety verdict."""
    entries={e['path']:e for e in inventory['entries'] if e['path'].startswith(persistence.DOVECOT_DIR+'/')}
    complete=inventory['state']=='collected' and persistence.DOVECOT_DIR not in inventory['missing_roots']
    files={};gaps=[]
    # The agent records a symlink without traversing it, so nothing behind one is observed.
    links=[p for p,e in entries.items() if e['kind']=='symlink']
    def behind_link(path):return any(path.startswith(link+'/') for link in links)
    for path,entry in entries.items():
        state=dovecot_state(entry)
        if state=='parsed' and not entry['dovecot']['truncated']:files[path]=dovecot_text(entry['dovecot'])
        elif state=='parsed':gaps.append({'code':'statements_truncated','path':path,'blocking':True})
    class Observed(dict):
        def __contains__(self,path):
            return dict.__contains__(self,path) or (complete and path.startswith(persistence.DOVECOT_DIR+'/') and path not in entries and not behind_link(path)
                                                   and not any(p.startswith(path+'/') for p in entries))
        def __getitem__(self,path):
            if dict.__contains__(self,path):return dict.__getitem__(self,path)
            if path in self:return None
            raise KeyError(path)
        def get(self,path,default=None):
            return dict.get(self,path) if dict.__contains__(self,path) else (None if path in self else default)
    globs={}
    for entry in entries.values():
        for item in entry.get('dovecot',{}).get('statements',()):
            if item['op']!='include' or not re.search(r'[*?\[]',item['pattern']):continue
            pattern=posixpath.normpath(posixpath.join(posixpath.dirname(entry['path']),item['pattern']))
            directory,name=posixpath.split(pattern)
            if not complete or behind_link(directory+'/') or directory in links or re.search(r'[*?\[]',directory) or not (directory+'/').startswith(persistence.DOVECOT_DIR+'/'):continue
            children={p[len(directory)+1:].split('/')[0] for p in entries if p.startswith(directory+'/')}
            matched=sorted(c for c in children if not c.startswith('.') and fnmatch.fnmatchcase(c,name))
            # A matching subdirectory is not a file Dovecot can read, and the inventory does not record it as one.
            if any(directory+'/'+c not in entries for c in matched):continue
            globs[pattern]=[directory+'/'+c for c in matched]
    result=dovecot_services.evaluate(files=Observed(files),globs=globs)
    gaps+=[{'code':'passwd_group_not_captured','blocking':True,'detail':'/etc/passwd and /etc/group are not captured, so service accounts are shown by name without UID or GID.'}]
    keep=('code','blocking','path','glob','source','line','service','user','group','key','section','limit')
    gaps+=[{k:(str(g[k])[:300] if isinstance(g[k],str) else g[k]) for k in keep if k in g} for g in result['gaps'] if g['code'] not in ('passwd_not_captured','group_not_captured')]
    return {'services':[{k:r[k] for k in ('service','builtin','argv','program','wrapper','exec_account','exec_account_basis','program_account',
                                          'expected_drop_account','service_user','drop_priv_before_exec','protocol','enabled','starts','source','line')}
                        for r in result['services']],
            'root_exec':result['root_exec'],'protocols':result['protocols'],'files':[f['path'] for f in result['files']],
            'config_accepted':result['config_accepted'],'complete':False,'gaps':gaps[:100],
            'origin':'not_assessed','authorizes_response':False,'contract_version':result['contract_version']}


def dovecot_text_search(entry):
    return ' '.join(i.get('pattern') or i.get('name') or i.get('value') or '' for i in entry.get('dovecot',{}).get('statements',()))


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
    """Mechanism counts; the at, anacron, TCP wrappers, kdump, request-key and ClamAV rows also report parsed jobs/commands and older-agent files."""
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
        if key=='kdump':
            found=[e for e in inventory['entries'] if e['path']==persistence.KDUMP_CONF]
            hooks=sum(len(e['kdump']['hooks']) for e in found if 'kdump' in e)
            label+=f' · {hooks} parsed hook{"" if hooks==1 else "s"}'+(' · refused by kdumpctl' if any(e.get('kdump',{}).get('starts') is False for e in found) else '')+(' · not reported by this agent version' if any(kdump_state(e)=='not_reported' for e in found) else '')
        if key in ('request_key','request_key_d'):
            found=[e for e in inventory['entries'] if mechanism(e['path'])[0]==key]
            rules=sum(len(e['request_key']['rules']) for e in found if 'request_key' in e)
            label+=f' · {rules} parsed rule{"" if rules==1 else "s"}'+(' · every lookup aborts' if any(e.get('request_key',{}).get('universal_abort_line') is not None for e in found) else '')+(' · not reported by this agent version' if any(request_key_state(e)=='not_reported' for e in found) else '')
        if key=='autofs':
            found=[e for e in inventory['entries'] if e['path']==persistence.AUTOFS_MASTER]
            entries=sum(len(autofs_view(e)['entries']) for e in found if autofs_state(e)=='resolved')
            label+=f' · {entries} master-map entr{"y" if entries==1 else "ies"} · map paths not looked up'+(' · not reported by this agent version' if any(autofs_state(e)=='not_reported' for e in found) else '')
        if key=='clamav':
            found=[e for e in inventory['entries'] if e['path'] in persistence.CLAMAV_FILES]
            commands=sum(len(clamav_view(e)['commands']) for e in found if 'clamav' in e)
            label+=f' · {commands} parsed event command{"" if commands==1 else "s"}'+(' · rejected by the option parser' if any(e.get('clamav',{}).get('error') for e in found) else '')+(' · not reported by this agent version' if any(clamav_state(e)=='not_reported' for e in found) else '')
        if key=='dovecot':
            found=[e for e in inventory['entries'] if mechanism(e['path'])[0]==key and e['kind']=='regular']
            states=[dovecot_state(e) for e in found]
            parsed=states.count('parsed')
            label+=f' · {parsed} parsed file{"" if parsed==1 else "s"}'+(' · not reported by this agent version' if 'not_reported' in states else '')
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
    rows=[];lookups=request_key_lookups(inventory);dovecot=None
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
        state=kdump_state(entry)
        if state:row['kdump_state']=state
        if 'kdump' in entry:row['kdump']=entry['kdump']
        state=request_key_state(entry)
        if state:row['request_key_state']=state
        if 'request_key' in entry:row['request_key']={**entry['request_key'],'lookups':lookups}
        state=autofs_state(entry)
        if state:row['autofs_state']=state
        if state=='resolved':row['autofs']=autofs_view(entry)
        state=clamav_state(entry)
        if state:row['clamav_state']=state
        if 'clamav' in entry:row['clamav']=clamav_view(entry)
        state=dovecot_state(entry)
        if state:row['dovecot_state']=state
        if state=='parsed':row['dovecot_statements']=len(entry['dovecot']['statements'])
        if entry['path']==dovecot_services.DEFAULT_CONFIG and state=='parsed':
            if dovecot is None:dovecot=dovecot_view(inventory)
            row['dovecot']=dovecot
        if entry['path'] in loading:row['cron_loading']=loading[entry['path']]
        jobs=' '.join(str(j['account'] or '')+' '+j['command'] for j in entry.get('cron',{}).get('jobs',()))
        # Built-in paths added after the baseline was collected were never compared, so they are not "unchanged".
        if changes is not None and within(entry['path'],newly) and not within(entry['path'],earlier):row['change']='not_in_baseline'
        if q.casefold() in (entry['path']+' '+label+' '+jobs+' '+anacron_text(entry)+' '+tcp_wrappers_text(entry)+' '+kdump_text(entry)+' '+request_key_text(entry)+' '+autofs_text(entry)+' '+clamav_text(entry)+' '+dovecot_text_search(entry)).casefold():rows.append(row)
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
