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


CRON_JOB_KEYS=frozenset({'line','schedule','account','command','redacted','command_truncated','stdin'})
CRON_ENVIRONMENT_KEYS=frozenset({'shell','shell_truncated','path','path_truncated'})


def validate_cron(cron):
    """Strictly validate optional parsed crontab jobs reported by newer agents."""
    if not isinstance(cron,dict) or set(cron)!={'format','jobs','unparsed','environment','truncated'} or cron['format'] not in ('system','user'):
        raise ValueError('Invalid cron job inventory')
    if any(type(cron[k]) is not int or cron[k]<0 for k in ('unparsed','environment')) or type(cron['truncated']) is not bool:
        raise ValueError('Invalid cron job inventory')
    jobs=cron['jobs']
    if not isinstance(jobs,list) or len(jobs)>CRON_FILE_JOBS:raise ValueError('Invalid cron job inventory')
    for job in jobs:
        if not isinstance(job,dict) or set(job) not in (CRON_JOB_KEYS,CRON_JOB_KEYS|CRON_ENVIRONMENT_KEYS):raise ValueError('Invalid cron job')
        # Newer agents report the SHELL/PATH the file assigned above the job (None: not set in the file).
        if 'shell' in job and any(type(job[k+'_truncated']) is not bool or (job[k] is not None and (not isinstance(job[k],str) or len(job[k])>CRON_COMMAND_LIMIT or '\x00' in job[k])) for k in ('shell','path')):
            raise ValueError('Invalid cron job')
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


ANACRONTAB='/etc/anacrontab'
ANACRON_KEYS={'parsed','jobs','environment','settings','unparsed','truncated','redacted'}
ANACRON_JOB_KEYS={'line','period_days','period_name','delay_minutes','identifier','command','command_truncated','redacted','duplicate_of_line'}
ANACRON_PERIODS={'daily':1,'weekly':7,'monthly':30,'yearly':365,'annually':365}


def validate_anacron(anacron,path):
    """Strictly validate optional parsed /etc/anacrontab jobs reported by newer agents."""
    if path!=ANACRONTAB:raise ValueError('Anacron jobs outside /etc/anacrontab')
    if not isinstance(anacron,dict) or set(anacron)!=ANACRON_KEYS:raise ValueError('Invalid anacron jobs')
    if any(type(anacron[k]) is not bool for k in ('parsed','truncated','redacted')) or any(type(anacron[k]) is not int or not 0<=anacron[k]<=1000000 for k in ('environment','unparsed')):
        raise ValueError('Invalid anacron jobs')
    settings=anacron['settings']
    if not isinstance(settings,dict) or set(settings)!={'start_hours_range','random_delay'}:raise ValueError('Invalid anacron settings')
    hours=settings['start_hours_range']
    if hours is not None and (not isinstance(hours,dict) or set(hours)!={'start','end'} or any(type(hours[k]) is not int or not 0<=hours[k]<=24 for k in ('start','end'))):
        raise ValueError('Invalid anacron settings')
    if settings['random_delay'] is not None and (type(settings['random_delay']) is not int or not 0<=settings['random_delay']<=999999):raise ValueError('Invalid anacron settings')
    jobs=anacron['jobs']
    if not isinstance(jobs,list) or len(jobs)>CRON_FILE_JOBS or (not anacron['parsed'] and (jobs or anacron['environment'] or anacron['unparsed'] or anacron['truncated'] or anacron['redacted'] or hours is not None or settings['random_delay'] is not None)):
        raise ValueError('Invalid anacron jobs')
    lines={}
    for job in jobs:
        if not isinstance(job,dict) or set(job)!=ANACRON_JOB_KEYS:raise ValueError('Invalid anacron job')
        if type(job['line']) is not int or job['line']<1 or job['line'] in lines or any(type(job[k]) is not bool for k in ('command_truncated','redacted')):raise ValueError('Invalid anacron job')
        if type(job['delay_minutes']) is not int or not 0<=job['delay_minutes']<=999999:raise ValueError('Invalid anacron job')
        name=job['period_name']
        if name is None:
            if type(job['period_days']) is not int or not 1<=job['period_days']<=99999:raise ValueError('Invalid anacron job')
        elif name not in ANACRON_PERIODS or job['period_days']!=ANACRON_PERIODS[name] or type(job['period_days']) is not int:raise ValueError('Invalid anacron job')
        if not isinstance(job['identifier'],str) or not re.fullmatch(r'[^\s/\x00]{1,255}',job['identifier']):raise ValueError('Invalid anacron job')
        if not isinstance(job['command'],str) or not 1<=len(job['command'])<=CRON_COMMAND_LIMIT or '\x00' in job['command']:raise ValueError('Invalid anacron job')
        duplicate=job['duplicate_of_line']
        if duplicate is not None and (type(duplicate) is not int or lines.get(duplicate)!=job['identifier']):raise ValueError('Invalid anacron job')
        lines[job['line']]=job['identifier']
    return len(jobs)


TCP_WRAPPERS_FILES=('/etc/hosts.allow','/etc/hosts.deny')
TCP_WRAPPERS_KEYS={'parsed','entries','skipped','option_errors','error_line','unconditional_line','aclexec_through_unconditional','commands','truncated','redacted'}
TCP_WRAPPERS_COMMAND_KEYS={'line','option','command','command_truncated','redacted','daemons','clients','matches_every_request','identity_options_ignored','after_runtime_checks'}
TCP_WRAPPERS_RUNTIME=('user','group','umask','linger','keepalive','nice','severity','setenv','rfc931','banners','aclexec')


def _tcpw_line(value):
    return value is None or (type(value) is int and 1<=value<=1000000)


def validate_tcp_wrappers(tcpw,path):
    """Strictly validate optional parsed hosts.allow/hosts.deny commands reported by newer agents (#1390)."""
    if path not in TCP_WRAPPERS_FILES:raise ValueError('TCP wrappers commands outside hosts.allow/hosts.deny')
    if not isinstance(tcpw,dict) or set(tcpw)!=TCP_WRAPPERS_KEYS:raise ValueError('Invalid TCP wrappers commands')
    if any(type(tcpw[k]) is not bool for k in ('parsed','aclexec_through_unconditional','truncated','redacted')) or any(type(tcpw[k]) is not int or not 0<=tcpw[k]<=1000000 for k in ('entries','skipped','option_errors')):
        raise ValueError('Invalid TCP wrappers commands')
    if not _tcpw_line(tcpw['error_line']) or not _tcpw_line(tcpw['unconditional_line']) or (tcpw['aclexec_through_unconditional'] and tcpw['unconditional_line'] is None):
        raise ValueError('Invalid TCP wrappers commands')
    commands=tcpw['commands']
    if not isinstance(commands,list) or len(commands)>CRON_FILE_JOBS or (not tcpw['parsed'] and (commands or tcpw['entries'] or tcpw['skipped'] or tcpw['option_errors'] or tcpw['error_line'] or tcpw['unconditional_line'] or tcpw['truncated'] or tcpw['redacted'])):
        raise ValueError('Invalid TCP wrappers commands')
    if tcpw['option_errors']>tcpw['entries'] or (commands and not tcpw['entries']):raise ValueError('Invalid TCP wrappers commands')
    previous=0
    for item in commands:
        if not isinstance(item,dict) or set(item)!=TCP_WRAPPERS_COMMAND_KEYS or item['option'] not in ('spawn','twist','aclexec'):raise ValueError('Invalid TCP wrappers command')
        if type(item['line']) is not int or not previous<=item['line']<=1000000 or item['line']<1 or (tcpw['error_line'] is not None and item['line']>=tcpw['error_line']):raise ValueError('Invalid TCP wrappers command')
        previous=item['line']
        if any(type(item[k]) is not bool for k in ('command_truncated','redacted','matches_every_request')):raise ValueError('Invalid TCP wrappers command')
        if not isinstance(item['command'],str) or not 1<=len(item['command'])<=CRON_COMMAND_LIMIT or '\x00' in item['command']:raise ValueError('Invalid TCP wrappers command')
        for key in ('daemons','clients'):
            tokens=item[key]
            if not isinstance(tokens,list) or len(tokens)>32 or any(not isinstance(t,str) or not 1<=len(t)<=255 or '\x00' in t for t in tokens):raise ValueError('Invalid TCP wrappers command')
        for key,allowed in (('identity_options_ignored',('user','group')),('after_runtime_checks',TCP_WRAPPERS_RUNTIME)):
            names=item[key]
            if not isinstance(names,list) or any(type(n) is not str or n not in allowed for n in names) or len(set(names))!=len(names):raise ValueError('Invalid TCP wrappers command')
    return len(commands)


KDUMP_CONF='/etc/kdump.conf'
KDUMP_KEYS={'parsed','starts','refusals','hooks','extra_bins','truncated','redacted'}
KDUMP_REFUSAL_KEYS={'line','option','code'}
KDUMP_REFUSALS=('unknown_option','deprecated_option','empty_value','duplicate_option','multiple_targets','multiple_mount_targets')
KDUMP_HOOK_KEYS={'line','source','stage','program','args','program_truncated','redacted','on_failure','observations'}
# source -> (stage, args, on_failure, observations that may be reported), in capture order.
KDUMP_HOOKS={'kdump_pre':('pre',[],'skip_dump_and_run_final_action',('value_has_whitespace','relative_path','pre_failure_skips_dump')),
             'core_collector':('dump',None,'dump_failed',('args_rewritten_at_capture',)),
             'kdump_post':('post',['<dump status>'],'warn',('value_has_whitespace','relative_path')),
             'kdump_emergency':('emergency',[],'warn',('value_has_whitespace','relative_path','runs_on_capture_failure'))}


def _kdump_text(value,limit=CRON_COMMAND_LIMIT):
    return isinstance(value,str) and 1<=len(value)<=limit and '\x00' not in value


def validate_kdump(kdump,path):
    """Strictly validate optional parsed /etc/kdump.conf hooks reported by newer agents (#1538)."""
    if path!=KDUMP_CONF:raise ValueError('kdump hooks outside /etc/kdump.conf')
    if not isinstance(kdump,dict) or set(kdump)!=KDUMP_KEYS:raise ValueError('Invalid kdump hooks')
    if any(type(kdump[k]) is not bool for k in ('parsed','truncated','redacted')) or type(kdump['extra_bins']) is not int or not 0<=kdump['extra_bins']<=65536:
        raise ValueError('Invalid kdump hooks')
    refusals,hooks=kdump['refusals'],kdump['hooks']
    if not isinstance(refusals,list) or not isinstance(hooks,list) or len(refusals)>CRON_FILE_JOBS:raise ValueError('Invalid kdump hooks')
    if not kdump['parsed']:
        if kdump['starts'] is not None or refusals or hooks or kdump['extra_bins'] or kdump['truncated'] or kdump['redacted']:raise ValueError('Invalid kdump hooks')
        return 0
    if kdump['starts'] is not (not refusals):raise ValueError('Invalid kdump hooks')
    previous=0
    for item in refusals:
        if not isinstance(item,dict) or set(item)!=KDUMP_REFUSAL_KEYS or item['code'] not in KDUMP_REFUSALS:raise ValueError('Invalid kdump refusal')
        if type(item['line']) is not int or not max(previous,1)<=item['line']<2048 or item['line']==previous:raise ValueError('Invalid kdump refusal')
        if not _kdump_text(item['option'],64):raise ValueError('Invalid kdump refusal')
        previous=item['line']
    if not kdump['starts']:
        if hooks or kdump['extra_bins']:raise ValueError('Invalid kdump hooks')
        return 0
    sources=[item.get('source') if isinstance(item,dict) else None for item in hooks]
    if 'core_collector' not in sources or sources!=[s for s in KDUMP_HOOKS if s in sources]:raise ValueError('Invalid kdump hooks')
    lines=set()
    for item in hooks:
        if set(item)!=KDUMP_HOOK_KEYS:raise ValueError('Invalid kdump hook')
        stage,args,on_failure,allowed=KDUMP_HOOKS[item['source']]
        if item['stage']!=stage or item['on_failure']!=on_failure:raise ValueError('Invalid kdump hook')
        line=item['line']
        if line is None:
            if item['source']!='core_collector':raise ValueError('Invalid kdump hook')
        elif type(line) is not int or not 1<=line<2048 or line in lines:raise ValueError('Invalid kdump hook')
        else:lines.add(line)
        if any(type(item[k]) is not bool for k in ('program_truncated','redacted')) or not _kdump_text(item['program']):raise ValueError('Invalid kdump hook')
        if args is None:
            if not isinstance(item['args'],list) or len(item['args'])>32 or any(not _kdump_text(a) for a in item['args']):raise ValueError('Invalid kdump hook')
        elif item['args']!=args:raise ValueError('Invalid kdump hook')
        names=item['observations']
        if not isinstance(names,list) or any(type(n) is not str or n not in allowed for n in names) or len(set(names))!=len(names):raise ValueError('Invalid kdump hook')
        if item['source']=='kdump_pre' and 'pre_failure_skips_dump' not in names:raise ValueError('Invalid kdump hook')
        if item['source']=='kdump_emergency' and 'runs_on_capture_failure' not in names:raise ValueError('Invalid kdump hook')
    return len(hooks)


REQUEST_KEY_CONF='/etc/request-key.conf'
REQUEST_KEY_DIR='/etc/request-key.d'
REQUEST_KEY_KEYS={'parsed','rules','aborts','universal_abort_line','last_byte_dropped','truncated','redacted'}
REQUEST_KEY_RULE_KEYS={'line','op','type','description','callout_info','pipe','command','command_truncated','redacted',
                       'kernel_upcall','requester_controlled','fails_when_selected','code_runs'}
REQUEST_KEY_ABORT_KEYS={'line','reason','scope','universal'}
REQUEST_KEY_CONTROLLED=('callout_info','description','keysub_payload','stdin_callout_info')
REQUEST_KEY_FAILURES=('program_without_slash','too_many_arguments','missing_macro_name','unsupported_macro','malformed_keysub')
# fgets(4098) and the 64 KiB agent parse limit bound the line count of a parsed file.
REQUEST_KEY_LINES=65536


def request_key_reads(path):
    """Whether /sbin/request-key reads this path by name (drop-ins must also be regular files)."""
    if path==REQUEST_KEY_CONF:return True
    parent,_,name=path.rpartition('/')
    return parent==REQUEST_KEY_DIR and not name.startswith('.') and len(name)>=5 and name.endswith('.conf')


def _request_key_pattern(value):
    return isinstance(value,str) and 1<=len(value)<=256 and '\x00' not in value


def validate_request_key(report,path):
    """Strictly validate an optional parsed request-key configuration file reported by newer agents (#1632)."""
    if not request_key_reads(path):raise ValueError('request-key rules outside files request-key reads')
    if not isinstance(report,dict) or set(report)!=REQUEST_KEY_KEYS:raise ValueError('Invalid request-key rules')
    if any(type(report[k]) is not bool for k in ('parsed','last_byte_dropped','truncated','redacted')):raise ValueError('Invalid request-key rules')
    rules,aborts,first=report['rules'],report['aborts'],report['universal_abort_line']
    if not isinstance(rules,list) or not isinstance(aborts,list) or len(rules)>CRON_FILE_JOBS or len(aborts)>CRON_FILE_JOBS:raise ValueError('Invalid request-key rules')
    if not report['parsed']:
        if rules or aborts or first is not None or report['last_byte_dropped'] or report['truncated'] or report['redacted']:raise ValueError('Invalid request-key rules')
        return 0
    if first is not None and (type(first) is not int or not 1<=first<=REQUEST_KEY_LINES):raise ValueError('Invalid request-key rules')
    lines=set();universal=[]
    for item in aborts:
        if not isinstance(item,dict) or set(item)!=REQUEST_KEY_ABORT_KEYS or item['reason'] not in ('line_too_long','syntax_error'):raise ValueError('Invalid request-key abort')
        if type(item['line']) is not int or not 1<=item['line']<=REQUEST_KEY_LINES or item['line'] in lines or type(item['universal']) is not bool:raise ValueError('Invalid request-key abort')
        scope=item['scope']
        if not isinstance(scope,list) or len(scope)>(0 if item['reason']=='line_too_long' else 4) or any(not _request_key_pattern(p) for p in scope):raise ValueError('Invalid request-key abort')
        if item['reason']=='line_too_long' and not item['universal']:raise ValueError('Invalid request-key abort')
        lines.add(item['line'])
        if item['universal']:universal.append(item['line'])
    # The first universal abort line is always recorded, even when the abort list itself is truncated.
    if universal and first!=min(universal):raise ValueError('Invalid request-key rules')
    if not universal and first is not None and (not report['truncated'] or len(aborts)<CRON_FILE_JOBS or first in lines):raise ValueError('Invalid request-key rules')
    for item in rules:
        if not isinstance(item,dict) or set(item)!=REQUEST_KEY_RULE_KEYS:raise ValueError('Invalid request-key rule')
        if type(item['line']) is not int or not 1<=item['line']<=REQUEST_KEY_LINES or item['line'] in lines:raise ValueError('Invalid request-key rule')
        lines.add(item['line'])
        if any(not _request_key_pattern(item[k]) for k in ('op','type','description','callout_info')):raise ValueError('Invalid request-key rule')
        if any(type(item[k]) is not bool for k in ('pipe','command_truncated','redacted','kernel_upcall')):raise ValueError('Invalid request-key rule')
        if not isinstance(item['command'],str) or len(item['command'])>CRON_COMMAND_LIMIT or '\x00' in item['command']:raise ValueError('Invalid request-key rule')
        names=item['requester_controlled']
        if not isinstance(names,list) or names!=sorted(set(names)) or any(n not in REQUEST_KEY_CONTROLLED for n in names) or ('stdin_callout_info' in names)!=item['pipe']:raise ValueError('Invalid request-key rule')
        failure=item['fails_when_selected']
        if failure is not None and failure not in REQUEST_KEY_FAILURES:raise ValueError('Invalid request-key rule')
        expected='never' if not item['kernel_upcall'] else 'fails_when_selected' if failure else 'on_matching_request'
        if item['code_runs']!=expected:raise ValueError('Invalid request-key rule')
    return len(rules)


CLAMAV_FILES={'/etc/clamav/clamd.conf':'clamd','/etc/clamav/freshclam.conf':'freshclam'}
CLAMAV_KEYS={'parsed','accepted','error','values','redacted'}
CLAMAV_VALUE_KEYS={'line','value','truncated','redacted'}
CLAMAV_REASONS=('example_config','missing_argument','missing_closing_quote','empty_argument','unknown_option',
                'incorrect_argument_format','parser_crash')
CLAMAV_COMMANDS=('VirusEvent','OnUpdateExecute','on-update-execute','OnErrorExecute','on-error-execute',
                 'OnOutdatedExecute','on-outdated-execute')
CLAMAV_KEPT={'clamd':('VirusEvent','User'),
             'freshclam':('OnUpdateExecute','on-update-execute','OnErrorExecute','on-error-execute',
                          'OnOutdatedExecute','on-outdated-execute','DatabaseOwner','user','daemon')}
CLAMAV_VALUE_LIMIT=256
# fgets(1024) chunks of the 1 MiB inventory limit bound the line number.
CLAMAV_LINES=1024*1024


def validate_clamav(report,path):
    """Strictly validate an optional parsed clamd.conf or freshclam.conf reported by newer agents (#1607)."""
    tool=CLAMAV_FILES.get(path)
    if tool is None:raise ValueError('ClamAV options outside the parsed configuration files')
    if not isinstance(report,dict) or set(report)!=CLAMAV_KEYS:raise ValueError('Invalid ClamAV options')
    if any(type(report[k]) is not bool for k in ('parsed','accepted','redacted')):raise ValueError('Invalid ClamAV options')
    values,error=report['values'],report['error']
    if not isinstance(values,dict):raise ValueError('Invalid ClamAV options')
    if not report['parsed']:
        if report['accepted'] or error is not None or values or report['redacted']:raise ValueError('Invalid ClamAV options')
        return 0
    if report['accepted']!=(error is None):raise ValueError('Invalid ClamAV options')
    if error is not None:
        if not isinstance(error,dict) or set(error)!={'line','reason'} or error['reason'] not in CLAMAV_REASONS:raise ValueError('Invalid ClamAV error')
        if type(error['line']) is not int or not 1<=error['line']<=CLAMAV_LINES:raise ValueError('Invalid ClamAV error')
    redacted=False
    for name,item in values.items():
        if name not in CLAMAV_KEPT[tool]:raise ValueError('ClamAV option not retained by agents')
        if not isinstance(item,dict) or set(item)!=CLAMAV_VALUE_KEYS:raise ValueError('Invalid ClamAV option')
        limit=CRON_COMMAND_LIMIT if name in CLAMAV_COMMANDS else CLAMAV_VALUE_LIMIT
        if type(item['line']) is not int or not 1<=item['line']<=CLAMAV_LINES:raise ValueError('Invalid ClamAV option')
        if error is not None and item['line']>=error['line']:raise ValueError('Invalid ClamAV option')
        if not isinstance(item['value'],str) or len(item['value'])>limit or '\x00' in item['value']:raise ValueError('Invalid ClamAV option')
        if type(item['truncated']) is not bool or type(item['redacted']) is not bool:raise ValueError('Invalid ClamAV option')
        if item['redacted'] and name not in CLAMAV_COMMANDS:raise ValueError('Invalid ClamAV option')
        redacted=redacted or item['redacted']
    if redacted!=report['redacted']:raise ValueError('Invalid ClamAV options')
    if len({item['line'] for item in values.values()})!=len(values):raise ValueError('Invalid ClamAV options')
    return sum(name in CLAMAV_COMMANDS for name in values)


AUTOFS_MASTER='/etc/auto.master'
AUTOFS_KEYS={'text','error'}
AUTOFS_TEXT_LIMIT=65536


def validate_autofs(autofs,path):
    """Strictly validate the optional bounded master-map text (#1375). Map paths are never observed."""
    if path!=AUTOFS_MASTER:raise ValueError('autofs master map outside /etc/auto.master')
    if not isinstance(autofs,dict) or set(autofs)!=AUTOFS_KEYS:raise ValueError('Invalid autofs master map')
    text,error=autofs['text'],autofs['error']
    if error is not None:
        if error not in ('over_limit','binary') or text is not None:raise ValueError('Invalid autofs master map')
        return 0
    if not isinstance(text,str) or len(text)>AUTOFS_TEXT_LIMIT or '\x00' in text or any(ord(c)>0xFF for c in text):raise ValueError('Invalid autofs master map')
    return 1


# Dovecot (#1620): the agent reduces every regular file under /etc/dovecot to the statement stream
# app/dovecot_services reads. Only section headers, include patterns and the global/service keys the
# contract evaluates keep values; every other value is dropped by the agent.
DOVECOT_DIR='/etc/dovecot'
DOVECOT_KEYS={'parsed','statements','truncated','dropped'}
DOVECOT_KEPT_KEYS=frozenset(('protocols','default_internal_user','default_login_user','libexec_dir','executable',
                             'user','group','drop_priv_before_exec','process_min_avail','protocol','chroot'))
DOVECOT_STATEMENT_KEYS={'error':{'line','op'},'close':{'line','op'},'include':{'line','op','optional','pattern'},
                        'open':{'line','op','kind','name'},'set':{'line','op','key','value','file','redacted'}}
DOVECOT_STATEMENTS=2000
DOVECOT_LINES=1024*1024
DOVECOT_VALUE=1024


def _dovecot_text(value,limit=DOVECOT_VALUE):
    return isinstance(value,str) and len(value)<=limit and '\x00' not in value and '\n' not in value and '\r' not in value


def validate_dovecot(report,path):
    """Strictly validate one file's Dovecot statement stream."""
    if not path.startswith(DOVECOT_DIR+'/'):raise ValueError('Dovecot statements outside /etc/dovecot')
    if not isinstance(report,dict) or set(report)!=DOVECOT_KEYS:raise ValueError('Invalid Dovecot statements')
    if type(report['parsed']) is not bool or type(report['truncated']) is not bool or type(report['dropped']) is not int or not 0<=report['dropped']<=DOVECOT_LINES:
        raise ValueError('Invalid Dovecot statements')
    items=report['statements']
    if not isinstance(items,list) or len(items)>DOVECOT_STATEMENTS or (not report['parsed'] and (items or report['truncated'] or report['dropped'])):
        raise ValueError('Invalid Dovecot statements')
    last=0
    for item in items:
        if not isinstance(item,dict) or item.get('op') not in DOVECOT_STATEMENT_KEYS or set(item)!=DOVECOT_STATEMENT_KEYS[item['op']]:
            raise ValueError('Invalid Dovecot statement')
        if type(item['line']) is not int or not last<item['line']<=DOVECOT_LINES:raise ValueError('Invalid Dovecot statement')
        last=item['line']
        if item['op']=='include' and (type(item['optional']) is not bool or not _dovecot_text(item['pattern']) or not item['pattern'].strip()):
            raise ValueError('Invalid Dovecot include')
        if item['op']=='open' and (not isinstance(item['kind'],str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}',item['kind']) or (item['name'] is not None and not _dovecot_text(item['name']))):
            raise ValueError('Invalid Dovecot section')
        if item['op']=='set':
            if not isinstance(item['key'],str) or not re.fullmatch('[A-Za-z0-9_/-]{1,128}',item['key']) or type(item['file']) is not bool or type(item['redacted']) is not bool:
                raise ValueError('Invalid Dovecot setting')
            kept=item['value'] is not None
            if kept and (item['key'] not in DOVECOT_KEPT_KEYS or item['file'] or not _dovecot_text(item['value'])):raise ValueError('Invalid Dovecot setting')
            if item['redacted'] and (not kept or item['key']!='executable'):raise ValueError('Invalid Dovecot setting')


# strongSwan swanctl (#1624): the agent reduces every regular *.conf file under /etc/swanctl and
# /etc/strongswan/swanctl to the statement stream app/strongswan_updown reads. Section names, include
# patterns and setting keys are kept; only updown values keep their text, every other value is dropped.
SWANCTL_DIRS=('/etc/swanctl','/etc/strongswan/swanctl')
SWANCTL_KEYS={'parsed','statements','truncated','dropped'}
SWANCTL_STATEMENT_KEYS={'error':{'line','op','code'},'close':{'line','op'},'include':{'line','op','pattern'},
                        'open':{'line','op','name'},'set':{'line','op','key','value','redacted'}}
SWANCTL_ERRORS=('syntax','unterminated_quote','escape_sequence')
SWANCTL_STATEMENTS=2000
SWANCTL_LINES=1024*1024+1
SWANCTL_NAME=1024


def swanctl_reads(path):
    return path.endswith('.conf') and any(path.startswith(d+'/') for d in SWANCTL_DIRS)


def _swanctl_text(value,limit=SWANCTL_NAME):
    return isinstance(value,str) and len(value)<=limit and '\x00' not in value


def validate_swanctl(report,path):
    """Strictly validate one file's swanctl statement stream."""
    if not swanctl_reads(path):raise ValueError('strongSwan statements outside the swanctl configuration')
    if not isinstance(report,dict) or set(report)!=SWANCTL_KEYS:raise ValueError('Invalid strongSwan statements')
    # Agents before #1680 also counted the value of the setting that hit the statement cap, so a truncated
    # file can report one more dropped value than statements; the view still blocks on truncated files.
    if type(report['parsed']) is not bool or type(report['truncated']) is not bool or type(report['dropped']) is not int or not 0<=report['dropped']<=SWANCTL_STATEMENTS+report['truncated']:
        raise ValueError('Invalid strongSwan statements')
    items=report['statements']
    if not isinstance(items,list) or len(items)>SWANCTL_STATEMENTS or (not report['parsed'] and (items or report['truncated'] or report['dropped'])):
        raise ValueError('Invalid strongSwan statements')
    last=1
    for index,item in enumerate(items):
        if not isinstance(item,dict) or item.get('op') not in SWANCTL_STATEMENT_KEYS or set(item)!=SWANCTL_STATEMENT_KEYS[item['op']]:
            raise ValueError('Invalid strongSwan statement')
        if type(item['line']) is not int or not last<=item['line']<=SWANCTL_LINES:raise ValueError('Invalid strongSwan statement')
        last=item['line']
        op=item['op']
        if op=='error':
            # Lexing gaps make strongSwan drop the whole file, so they are the only statement; a syntax gap ends the file.
            if item['code'] not in SWANCTL_ERRORS or index!=len(items)-1 or (item['code']!='syntax' and len(items)!=1) or report['truncated']:
                raise ValueError('Invalid strongSwan error')
        # An empty pattern is reported as-is: strongSwan ignores it and keeps loading the file (#1680).
        if op=='include' and not _swanctl_text(item['pattern']):raise ValueError('Invalid strongSwan include')
        if op=='open' and not _swanctl_text(item['name']):raise ValueError('Invalid strongSwan section')
        if op=='set':
            if not _swanctl_text(item['key']) or type(item['redacted']) is not bool:raise ValueError('Invalid strongSwan setting')
            if item['key']=='updown':
                if not _swanctl_text(item['value'],CRON_COMMAND_LIMIT):raise ValueError('Invalid strongSwan updown')
            elif item['value'] is not None or item['redacted']:raise ValueError('strongSwan value not retained by agents')
    return len(items)



# LVM2 program settings (#1599): agents parse /etc/lvm/lvm.conf and lvmlocal.conf and keep only the reduced
# tree app/lvm_commands evaluates (target/agent.py parse_lvm_conf).
LVM_FILES=('/etc/lvm/lvm.conf','/etc/lvm/lvmlocal.conf')
LVM_KEYS={'parsed','error','sections','inexact','nodename'}
LVM_SETTINGS={'global':('thin_check_executable','thin_dump_executable','thin_repair_executable','cache_check_executable',
                        'cache_dump_executable','cache_repair_executable','vdo_format_executable','fsadm_executable',
                        'lvmlockctl_kill_command','tags'),
              'dmeventd':('executable','mirror_library','raid_library','snapshot_library','thin_library','vdo_library',
                          'thin_command','vdo_command','tags')}
LVM_REASONS=('nul_byte','invalid_utf8','unterminated_string','expected_value','unexpected_token','empty_section_identifier','nesting_limit')
LVM_LINES=1024*1024
LVM_VALUES=64
LVM_TAGS=64


def _lvm_text(value,limit):
    return isinstance(value,str) and len(value)<=limit and '\x00' not in value


def _lvm_values(values):
    if not isinstance(values,list) or not 1<=len(values)<=LVM_VALUES:raise ValueError('Invalid LVM value')
    for item in values:
        if not isinstance(item,list) or len(item)!=2:raise ValueError('Invalid LVM value')
        kind,value=item
        if kind=='string':ok=_lvm_text(value,CRON_COMMAND_LIMIT)
        elif kind=='int':ok=type(value) is int and -(1<<63)<=value<(1<<64)
        elif kind=='float':ok=isinstance(value,str) and 1<=len(value)<=64 and re.fullmatch(r'[0-9.+-]+',value) is not None
        elif kind=='empty_array':ok=value is None and len(values)==1
        else:ok=False
        if not ok:raise ValueError('Invalid LVM value')


def _lvm_assignments(items,allowed):
    if not isinstance(items,list) or len(items)>len(allowed):raise ValueError('Invalid LVM section')
    keys=[]
    for item in items:
        if not isinstance(item,dict) or set(item)!={'key','values'} or item['key'] not in allowed:raise ValueError('LVM value not retained by agents')
        if item['values'] is not None or item['key']!='tags' or 'hosttags' in allowed or 'host_list' in allowed:_lvm_values(item['values'])
        keys.append(item['key'])
    if len(set(keys))!=len(keys):raise ValueError('Duplicate LVM value')


def validate_lvm(report,path):
    """Strictly validate the reduced LVM configuration tree reported by newer agents (#1599)."""
    if path not in LVM_FILES:raise ValueError('LVM settings outside /etc/lvm')
    if not isinstance(report,dict) or set(report)!=LVM_KEYS or type(report['parsed']) is not bool:raise ValueError('Invalid LVM settings')
    if report['nodename'] is not None and not (_lvm_text(report['nodename'],255) and report['nodename']):raise ValueError('Invalid LVM node name')
    inexact=report['inexact'];sections=report['sections'];error=report['error']
    if not isinstance(inexact,list) or len(inexact)>LVM_VALUES or not all(_lvm_text(i,600) and i for i in inexact):raise ValueError('Invalid LVM inexact values')
    if not isinstance(sections,list):raise ValueError('Invalid LVM settings')
    if not report['parsed']:
        if not isinstance(error,dict) or set(error)!={'reason','line'} or error['reason'] not in LVM_REASONS:raise ValueError('Invalid LVM error')
        if error['reason'] in ('nul_byte','invalid_utf8'):
            if error['line'] is not None:raise ValueError('Invalid LVM error')
        elif type(error['line']) is not int or not 1<=error['line']<=LVM_LINES:raise ValueError('Invalid LVM error')
        if sections or inexact:raise ValueError('Rejected LVM configuration retains settings')
        return 0
    if error is not None or len(sections)>3:raise ValueError('Invalid LVM settings')
    keys=[]
    for section in sections:
        if not isinstance(section,dict) or section.get('key') not in ('global','dmeventd','tags'):raise ValueError('LVM section not retained by agents')
        keys.append(section['key'])
        if section['key']=='tags':
            if set(section)!={'key','values','tags'}:raise ValueError('Invalid LVM tags')
            _lvm_assignments(section['values'],('hosttags',))
            tags=section['tags']
            if not isinstance(tags,list) or len(tags)>LVM_TAGS:raise ValueError('Invalid LVM tags')
            names=[]
            for tag in tags:
                if not isinstance(tag,dict) or set(tag)!={'key','values'} or not _lvm_text(tag['key'],255) or not tag['key']:raise ValueError('Invalid LVM tag')
                names.append(tag['key'])
                if not isinstance(tag['values'],list) or len(tag['values'])>2:raise ValueError('Invalid LVM tag')
                _lvm_assignments(tag['values'],('host_list','host_filter'))
            if len(set(names))!=len(names):raise ValueError('Duplicate LVM tag')
        else:
            if set(section)!={'key','values'}:raise ValueError('Invalid LVM section')
            _lvm_assignments(section['values'],LVM_SETTINGS[section['key']])
    if len(set(keys))!=len(keys):raise ValueError('Duplicate LVM section')
    return sum(len(s['values']) for s in sections if s['key']!='tags')

def metadata(row):
    """Entry metadata without parsed cron/at/anacron/TCP wrappers/kdump/request-key/autofs/ClamAV/Dovecot/strongSwan detail, for comparisons and incident evidence."""
    return {k:v for k,v in row.items() if k not in ('cron','at','anacron','tcp_wrappers','kdump','request_key','autofs','clamav','dovecot','strongswan','lvm')} if row is not None else None


MAX_SCOPE=64


def validate(inventory):
    if not isinstance(inventory,dict) or inventory.get('state') not in ('collected','incomplete'):
        raise ValueError('Invalid persistence inventory')
    scope=inventory.get('scope');entries=inventory.get('entries');gaps=inventory.get('gaps');missing=inventory.get('missing_roots')
    # Built-in scope grows with each additive startup mechanism, and agents add up to 16 custom paths
    # (target/agent.py validate_custom_paths), so the bound leaves room for both (#1666).
    if not isinstance(scope,list) or not 1<=len(scope)<=MAX_SCOPE or not all(path_ok(p) for p in scope) or len(set(scope))!=len(scope):
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
        if 'anacron' in row:
            if row['kind']!='regular':raise ValueError('Anacron jobs require a regular file')
            validate_anacron(row['anacron'],path)
        if 'tcp_wrappers' in row:
            if row['kind']!='regular':raise ValueError('TCP wrappers commands require a regular file')
            validate_tcp_wrappers(row['tcp_wrappers'],path)
        if 'kdump' in row:
            if row['kind']!='regular':raise ValueError('kdump hooks require a regular file')
            validate_kdump(row['kdump'],path)
        if 'request_key' in row:
            if row['kind']!='regular':raise ValueError('request-key rules require a regular file')
            validate_request_key(row['request_key'],path)
        if 'autofs' in row:
            if row['kind']!='regular':raise ValueError('autofs master map requires a regular file')
            validate_autofs(row['autofs'],path)
        if 'clamav' in row:
            if row['kind']!='regular':raise ValueError('ClamAV options require a regular file')
            validate_clamav(row['clamav'],path)
        if 'lvm' in row:
            if row['kind']!='regular':raise ValueError('LVM settings require a regular file')
            validate_lvm(row['lvm'],path)
        if 'dovecot' in row:
            if row['kind']!='regular':raise ValueError('Dovecot statements require a regular file')
            validate_dovecot(row['dovecot'],path)
        if 'strongswan' in row:
            if row['kind']!='regular':raise ValueError('strongSwan statements require a regular file')
            validate_swanctl(row['strongswan'],path)
    if jobs>CRON_TOTAL_JOBS:raise ValueError('Too many cron jobs')
    if inventory['state']=='collected' and (gaps or inventory['skipped']):raise ValueError('Persistence coverage contradicts collected state')


# Paths later agents added to built-in startup scope. Keep this list explicit and
# reviewed: only these additions compare against an earlier inventory's scope.
# TCP wrappers access files (#1390): spawn/twist/aclexec run commands when libwrap daemons accept connections.
# rsnapshot configuration (#1530): cmd_preexec/cmd_postexec, backup_script/backup_exec and backtick
# include_conf commands run as the invoking user, root from the packaged cron entry.
# System git configuration (#1535): aliases, pagers, editors, helpers, hooks and drivers run on
# git invocations by every account, including root cron jobs and package hooks.
# kdump configuration (#1538): kdump_pre, kdump_post, kdump_emergency and core_collector run as
# root in the crash-capture environment after a kernel crash.
# autofs master map (#1375): automount runs program maps it names as root on every key lookup.
# keyutils request-key configuration (#1632): the kernel's key upcall runs /sbin/request-key as
# root, which runs the program the best-matching rule names with requester-chosen arguments.
# ClamAV configuration (#1607): clamd runs VirusEvent on every detection and freshclam runs its
# On*Execute commands on update events; /etc/clamav on Debian, /etc/clamd.d and /etc/freshclam.conf on RPM.
# Dovecot configuration (#1620): the master process runs as root and execs every service executable
# its configuration names, as root unless drop_priv_before_exec is set; /etc/dovecot on both families.
# strongSwan swanctl configuration (#1624): charon runs each child's updown command as root through /bin/sh
# on CHILD_SA up/down; /etc/swanctl on Debian, /etc/strongswan (swanctl/ and strongswan.conf) on RPM.
# runit service directories (#1628): runsvdir (as root) makes runsv exec each service's run, finish,
# log/run and control programs; /etc/service (a symlink on Debian), /etc/runit and /etc/sv.
# lighttpd configuration (#1603): include_shell commands run as root while the configuration is parsed,
# piped loggers and FastCGI/SCGI bin-path backends as server.username; /etc/lighttpd on both families.
# LVM2 configuration cascade (#1599): lvm commands run thin/cache check, dump and repair executables
# and dmeventd loads plugins and runs thin/vdo commands as root; /etc/lvm/lvm.conf and lvmlocal.conf
# only. A custom /etc/lvm saved earlier already observed them, so they keep comparing.
# PostgreSQL configuration (#1597): the server runs archive, restore, recovery and passphrase commands
# through /bin/sh and loads preload libraries as postgres; /etc/postgresql/<version>/<cluster> on Debian.
# ISC dhcpd configuration (#1593): dhcpd runs execute() programs on lease commit, release and expiry
# as its process user, and global-scope ones as root at every start; /etc/dhcp/dhcpd.conf and
# dhcpd6.conf, and the Debian-family /etc/default/isc-dhcp-server command-line defaults, only.
ADDITIVE_BUILTIN_SCOPE=('/etc/anacrontab','/etc/hosts.allow','/etc/hosts.deny','/etc/rsnapshot.conf','/etc/gitconfig',
                        '/etc/kdump.conf','/etc/auto.master','/etc/request-key.conf','/etc/request-key.d',
                        '/etc/clamav','/etc/clamd.d','/etc/freshclam.conf','/etc/dovecot',
                        '/etc/swanctl','/etc/strongswan','/etc/service','/etc/runit','/etc/sv','/etc/lighttpd',
                        '/etc/lvm/lvm.conf','/etc/lvm/lvmlocal.conf',
                        '/etc/postgresql',
                        '/etc/dhcp/dhcpd.conf','/etc/dhcp/dhcpd6.conf','/etc/default/isc-dhcp-server')
NEWLY_IN_SCOPE_NOTE=(' Newly covered built-in paths are not in the earlier inventory, so they are listed separately '
                     'and not reported as added; collect a new baseline to include them in future comparisons.')


def compare(before,after):
    result={'state':'unavailable','changes':[], 'note':'No comparable complete prior inventory; absence is not evidence of removal.'}
    try:validate(before);validate(after)
    except ValueError:return result
    if before['state']!='collected' or after['state']!='collected':return result
    added=set(after['scope'])-set(before['scope'])
    def within(path,roots):return any(path==root or path.startswith(root+'/') for root in roots)
    # A custom path inside a directory that built-in scope added later is covered by it,
    # so a later agent stops listing it separately; that is not a narrower scope.
    removed=set(before['scope'])-set(after['scope'])
    if not added<=set(ADDITIVE_BUILTIN_SCOPE) or not all(within(path,added) for path in removed):
        return {**result,'note':'Inventory scope changed; collect another complete inventory with the same scope.'}
    # Paths a later agent added to built-in scope were never observed by the earlier
    # inventory, so their files are newly covered rather than added on the host.
    # A built-in file inside an earlier custom directory (#1599) was observed by that directory.
    def previously_scoped(path):return within(path,before['scope'])
    # Parsed cron detail is administrator-view data; change evidence stays metadata-only.
    old={r['path']:metadata(r) for r in before['entries']};new={r['path']:metadata(r) for r in after['entries'] if previously_scoped(r['path'])}
    changes=[]
    fields=('kind','sha256','target','uid','gid','mode','size')
    for path in sorted(old.keys()|new.keys()):
        previous=old.get(path);current=new.get(path)
        changed=[key for key in fields if (previous or {}).get(key)!=(current or {}).get(key)]
        if previous is None or current is None or changed:
            changes.append({'path':path,'kind':'added' if previous is None else 'removed' if current is None else 'changed',
                            'fields':changed,'before':previous,'after':current})
    compared={'state':'compared','changes':changes,'note':'Observed changes between complete inventories, not an approved baseline or a malware verdict. Modification time alone is ignored.'}
    newly=sorted(path for path in added if not within(path,before['scope']))
    if newly:compared['newly_in_scope']=newly
    # Earlier custom paths now inside new built-in scope were compared, not newly covered.
    if removed:compared['previously_custom']=sorted(removed)
    return compared


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
    if comparison['state']=='compared':
        comparison['note']='Compared with the administrator-reviewed startup baseline; matches are not a clean-host verdict.'
        if comparison.get('newly_in_scope'):comparison['note']+=NEWLY_IN_SCOPE_NOTE
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
