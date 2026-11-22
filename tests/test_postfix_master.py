"""Postfix master.cf contract (#1338). Vectors follow Postfix 3.8.6 master_ent.c, readlline.c, pipe.c and spawn.c."""
from __future__ import annotations

from app import postfix_master as pm

MAIN = {'daemon_directory': '/usr/lib/postfix/sbin', 'compatibility_level': '3.6'}


def run(text, main=MAIN, **kw):
    return pm.evaluate(master_cf=text, main_cf=main, **kw)


def by_name(result):
    return {(s['name'], s['type']): s for s in result['services']}


def test_pipe_filter_command_user_and_macros():
    r = run('filter unix - n n - 10 pipe\n  flags=Rq user=filter:mail null_sender=\n'
            '  argv=/usr/local/bin/filter.sh -f ${sender} -- ${recipient}\n')
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed'
    s = by_name(r)[('filter', 'unix')]
    assert s['program'] == '/usr/lib/postfix/sbin/pipe' and s['starts_as'] == 'root'
    assert s['privileges'] == 'keeps_root'
    cmd = s['external_command']
    assert cmd['status'] == 'runs' and cmd['user'] == 'filter' and cmd['group'] == 'mail'
    assert cmd['argv'] == ['/usr/local/bin/filter.sh', '-f', '${sender}', '--', '${recipient}']
    assert cmd['macros'] == ['sender', 'recipient'] and len(cmd['command_sha256']) == 64


def test_continuations_drop_comments_and_join_without_separator():
    lines = pm.logical_lines('a unix - n n - - spawn\n# c\n\n user=x\n#d\n\targv=/x\nb unix\n')
    assert lines == [(1, 'a unix - n n - - spawn user=x\targv=/x'), (7, 'b unix')]
    # A logical line that starts with whitespace is skipped with a warning.
    assert pm.logical_lines('  orphan unix - - - - - x\nok unix - - - - - y\n') == [(2, 'ok unix - - - - - y')]


def test_last_duplicate_wins_and_keeps_first_position():
    r = run('smtp inet n - y - - smtpd\npickup unix n - y 60 1 pickup\nsmtp inet n - y - - smtpd -o x=y\n')
    services = [s for s in r['services'] if s['starts']]
    assert [s['name'] for s in services] == ['smtp', 'pickup']
    assert services[0]['line'] == 3 and services[0]['overridden_lines'] == [1]
    assert services[0]['args'][-2:] == ['-o', 'x=y']


def test_inet_identity_canonicalises_numeric_and_mapped_ports():
    text = 'smtp inet n - y - - smtpd\n25 inet n - y - - smtpd -o y=z\n'
    r = run(text, inet_services={'smtp': 25})
    assert [s['line'] for s in r['services']] == [2] and r['complete']
    unmapped = run(text)
    assert not unmapped['complete']
    assert any(g['code'] == 'identity_unresolved' for g in unmapped['gaps'])
    # Distinct numeric endpoints never collide, even without a services map.
    assert run('127.0.0.1:25 inet n - y - - smtpd\n[::1]:25 inet n - y - - smtpd\n')['complete']


def test_brace_grouping_and_errors():
    r = run('submission inet n - y - - smtpd -o { smtpd_client_restrictions = a, b }\n')
    assert by_name(r)[('submission', 'inet')]['args'][-1] == 'smtpd_client_restrictions = a, b'
    assert run('x unix - - y - - smtpd -o {a=b\n')['status'] == 'config_error'
    assert run('x unix - - y - - smtpd {a=b}c\n')['status'] == 'config_error'


def test_master_refusals_start_nothing():
    for text in ('x bogus - - - - - smtpd\n', 'x inet y - - - - smtpd\n', 'x unix - - - - -\n',
                 'x unix maybe - - - - smtpd\n', 'x unix - - - abc - smtpd\n', 'x unix - - - - - -\n',
                 'smtp: inet n - - - - smtpd\n'):
        r = run('ok unix - - - - - pickup\n' + text)
        assert r['status'] == 'config_error' and r['services'] == [], text


def test_master_service_disable_skips_before_validation():
    main = {**MAIN, 'master_service_disable': 'bad.unix, !smtp/inet inet'}
    r = run('bad unix nonsense\nsmtp inet n - y - - smtpd\nother inet n - y - - smtpd\n', main=main)
    s = by_name(r)
    assert s[('bad', 'unix')]['starts'] is False and s[('smtp', 'inet')]['starts'] is True
    assert s[('other', 'inet')]['starts'] is False
    off = run('smtp inet n - y - - smtpd\n', main={**MAIN, 'inet_protocols': ''})
    assert by_name(off)[('smtp', 'inet')]['starts'] is False


def test_defaults_wakeup_and_master_arguments():
    r = run('qmgr unix n - - 300? 1 qmgr\nproxy unix - - - - 0 /x/proxymap\nlmtp unix - - - - - lmtp\n',
            main={**MAIN, 'compatibility_level': '0'})
    s = by_name(r)
    assert s[('qmgr', 'unix')]['conditional_wakeup'] and s[('qmgr', 'unix')]['args'] == [
        'qmgr', '-l', '-t', 'unix', '-u', '-c']
    assert s[('proxy', 'unix')]['args'] == ['/x/proxymap', '-z', '-n', 'proxy', '-t', 'unix', '-u', '-c']
    assert s[('lmtp', 'unix')]['max_proc'] == 100 and s[('lmtp', 'unix')]['privileges'] == 'drops_to_mail_owner'


def test_daemon_refusals_report_service_but_no_command():
    cases = {
        'pipe user=root argv=/bin/sh': 'root',
        'pipe user=x:root argv=/bin/sh': 'group',
        'pipe user=postfix argv=/bin/sh': 'mail system owner',
        'pipe argv=/bin/sh': 'missing user',
        'pipe user=x': 'missing argv',
        'pipe user=x bogus=1 argv=/bin/sh': 'unknown attribute',
        'pipe flags=Z user=x argv=/bin/sh': 'unknown flag',
        'spawn flags=R user=x argv=/bin/sh': 'unknown attribute',
        'pipe -o novalue user=x argv=/bin/sh': '-o',
        'pipe -k user=x argv=/bin/sh': 'invalid option',
        'pipe -o =v user=x argv=/bin/sh': '-o',
        'pipe size=1k user=x argv=/bin/sh': 'size',
    }
    for tail, words in cases.items():
        r = run('t unix - n n - - ' + tail + '\n')
        cmd = r['services'][0]['external_command']
        assert r['status'] == 'loads' and cmd['status'] == 'daemon_refused', tail
        assert words in cmd['detail'] and cmd['argv'] is None, tail


def test_getopt_stops_at_first_non_option():
    r = run('t unix - n n - - spawn -o a=b -v user=x -o c=d argv=/bin/cmd -o e\n')
    cmd = r['services'][0]['external_command']
    assert cmd['status'] == 'daemon_refused' and 'unknown attribute' in cmd['detail']
    ok = run('t unix - n n - - spawn -o a=b -- user=x argv=/bin/cmd -o e\n')['services'][0]['external_command']
    assert ok['status'] == 'runs' and ok['argv'] == ['/bin/cmd', '-o', 'e']


def test_fail_closed_inputs():
    assert run(None)['status'] == 'unresolved' and not run(None)['complete']
    for raw in (b'x unix - - - - - a\0', b'\xff\xfe', 'x' * (pm.MAX_TEXT + 1)):
        r = run(raw)
        assert r['status'] == 'unresolved' and not r['complete']
    no_main = run('x unix - - - - - pickup\n', main=None)
    assert not no_main['complete'] and no_main['services'][0]['program'] is None
    expanded = run('x unix - - - - - pickup\n', main={**MAIN, 'daemon_directory': '$prefix/sbin'})
    assert any(g['code'] == 'parameter_expansion_unresolved' for g in expanded['gaps'])
    assert not expanded['complete']


def test_unprivileged_pipe_is_reported_with_a_caveat():
    r = run('t unix - y n - - pipe user=x argv=/bin/cmd\n')
    cmd = r['services'][0]['external_command']
    assert cmd['status'] == 'runs' and 'mail owner' in cmd['detail']
