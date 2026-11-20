"""Tests for the pure NUT upsmon command contract (#1247).

Expected outcomes follow clients/upsmon.c and common/parseconf.c in NUT v2.8.1.
"""
from app import nut_upsmon as nu

PATH = '/etc/nut/upsmon.conf'
ENV = {}
ARGV = ['-F']  # nut-monitor.service: ExecStart=/sbin/upsmon -F
# The shipped upsmon.conf.sample defaults, plus a MONITOR line with a password.
SAMPLE = """# Network UPS Tools: example upsmon configuration
MONITOR myups@localhost 1 upsmon s3cretPassw0rd primary
MINSUPPLIES 1
SHUTDOWNCMD "/sbin/shutdown -h +0"
POLLFREQ 5
POWERDOWNFLAG /etc/killpower
"""


def run(text=SAMPLE, argv=ARGV, env=ENV, path=PATH, **kw):
    return nu.assess(text, argv, env, path, **kw)


def cmd(result, kind):
    return next((c for c in result['commands'] if c['kind'] == kind), None)


def event(result, name):
    return next(e for e in result['events'] if e['event'] == name)


def test_sample_runs_shutdown_as_root_and_no_notifycmd():
    r = run()
    assert r['complete'] and r['gaps'] == []
    shut = cmd(r, 'SHUTDOWNCMD')
    assert shut['command'] == '/sbin/shutdown -h +0' and shut['user'] == 'root'
    assert shut['process'] == 'privileged_parent' and shut['line'] == 4
    assert cmd(r, 'NOTIFYCMD') is None
    assert all(e['flags'] == ['SYSLOG', 'WALL'] and not e['runs_notifycmd'] for e in r['events'])
    assert r['origin'] == 'not_assessed' and r['verdict'] is None


def test_monitor_and_certident_secrets_never_copied():
    text = SAMPLE + 'CERTIDENT myname anotherSecret\nBOGUS topsecretvalue here\n'
    blob = repr(run(text))
    for secret in ('s3cretPassw0rd', 'anotherSecret', 'topsecretvalue', 'BOGUS'):
        assert secret not in blob


def test_notifycmd_runs_as_run_as_user_only_for_exec_events():
    text = SAMPLE + ('NOTIFYCMD /usr/local/bin/notify.sh\nRUN_AS_USER nutmon\n'
                     'NOTIFYFLAG ONBATT SYSLOG+EXEC\nnotifyflag lowbatt EXEC\n'
                     'NOTIFYFLAG COMMBAD EXEC+IGNORE\n')
    r = run(text)
    n = cmd(r, 'NOTIFYCMD')
    assert n['user'] == 'nutmon' and n['process'] == 'unprivileged_child'
    # Directive names are exact-case: the lowercase notifyflag line is ignored.
    assert n['events'] == ['ONBATT']
    assert event(r, 'COMMBAD')['flags'] == ['EXEC', 'IGNORE'] and not event(r, 'COMMBAD')['runs_notifycmd']
    assert {'line': 10, 'status': 'invalid_directive'} in r['line_notes']
    assert r['run_as_user'] == {'name': 'nutmon', 'source': 'config', 'line': 8,
                                'applies_to': 'monitoring_and_notify', 'account_resolution': 'not_assessed'}


def test_event_name_case_insensitive_flags_exact_and_replace():
    text = SAMPLE + 'NOTIFYCMD /n\nNOTIFYFLAG onbatt EXEC\nNOTIFYFLAG ONBATT exec+WALL\n'
    r = run(text)
    # The second line resets ONBATT; lowercase "exec" is an unknown flag.
    assert event(r, 'ONBATT')['flags'] == ['WALL'] and cmd(r, 'NOTIFYCMD') is None
    assert {'line': 9, 'status': 'unknown_notify_flag', 'directive': 'NOTIFYFLAG'} in r['line_notes']


def test_unknown_event_leaves_flags_unchanged():
    r = run(SAMPLE + 'NOTIFYCMD /n\nNOTIFYFLAG ONBAT EXEC\n')
    assert all(e['flags'] == ['SYSLOG', 'WALL'] for e in r['events'])
    assert {'line': 8, 'status': 'unknown_notify_event', 'directive': 'NOTIFYFLAG'} in r['line_notes']


def test_single_process_mode_runs_notify_as_root():
    r = run(SAMPLE + 'NOTIFYCMD /n\nNOTIFYFLAG FSD EXEC\nRUN_AS_USER nut\n', argv=['-F', '-p'])
    assert r['mode'] == 'single_root'
    assert cmd(r, 'NOTIFYCMD')['user'] == 'root' and cmd(r, 'SHUTDOWNCMD')['process'] == 'single_root_process'


def test_run_as_user_precedence():
    text = SAMPLE + 'NOTIFYCMD /n\nNOTIFYFLAG FSD EXEC\n'
    assert cmd(run(text), 'NOTIFYCMD')['user'] == 'nut'
    assert run(text, default_user='ups')['run_as_user']['name'] == 'ups'
    r = run(text, argv=['-F', '-u', 'root'])
    assert cmd(r, 'NOTIFYCMD')['user'] == 'root' and r['run_as_user']['source'] == 'argv'
    # The file is read after the options, so RUN_AS_USER wins over -u.
    r = run(text + 'RUN_AS_USER nut\n', argv=['-Furoot'])
    assert cmd(r, 'NOTIFYCMD')['user'] == 'nut'


def test_last_value_wins_and_too_few_words():
    text = 'SHUTDOWNCMD /a\nSHUTDOWNCMD /b\nSHUTDOWNCMD\nNOTIFYMSG ONBATT\n'
    r = run(text)
    assert cmd(r, 'SHUTDOWNCMD')['command'] == '/b'
    assert {'line': 3, 'status': 'invalid_directive', 'directive': 'SHUTDOWNCMD'} in r['line_notes']
    assert {'line': 4, 'status': 'invalid_directive', 'directive': 'NOTIFYMSG'} in r['line_notes']


def test_tokenizer_quotes_escapes_comments_and_equals():
    lines = nu.tokenize('A "b c" d\\ e # x\nK=V\n"x\ny" z\nQ "a#b" tail\n\\\nW v')
    assert lines[0] == (1, ['A', 'b c', 'd e'], False)
    assert lines[1] == (2, ['K', '=', 'V'], False)
    # A quoted word spans the newline, and the newline byte is discarded.
    assert lines[2] == (3, ['xy', 'z'], False)
    # '#' inside quotes is a parse error; parsing resumes after it.
    assert lines[3] == (4, ['Q', 'a'], True)
    # Outside quotes a '"' inside a word is literal.
    assert lines[4] == (5, ['b"', 'tail'], False)
    # Backslash-newline continues the line.
    assert lines[-1][1] == ['W', 'v']


def test_parse_error_resumes_mid_line_into_a_directive():
    # The text after the in-quote '#' is read as its own line.
    r = run('X "#" SHUTDOWNCMD /tmp/evil\n')
    assert cmd(r, 'SHUTDOWNCMD') is None
    lines = nu.tokenize('X "#SHUTDOWNCMD /tmp/evil\n')
    assert lines[0][2] is True and lines[1][1] == ['SHUTDOWNCMD', '/tmp/evil']
    r = run('X "#SHUTDOWNCMD /tmp/evil\n')
    assert cmd(r, 'SHUTDOWNCMD')['command'] == '/tmp/evil'


def test_equals_word_becomes_the_command():
    assert cmd(run('SHUTDOWNCMD=/sbin/halt\n'), 'SHUTDOWNCMD')['command'] == '='


def test_control_and_non_ascii_bytes_discarded_but_split_words():
    lines = nu.tokenize('SHUTDOWNCMD \x01/sbin/xéy\n')
    assert lines[0][1] == ['SHUTDOWNCMD', '/sbin/xy']
    # A non-ASCII byte at a word start opens an empty word.
    assert nu.tokenize('A é B\n')[0][1] == ['A', '', 'B']


def test_word_and_arg_limits():
    long = 'x' * 600
    assert nu.tokenize(f'SHUTDOWNCMD {long}\n')[0][1][1] == 'x' * 512
    words = ' '.join(f'w{i}' for i in range(40))
    assert len(nu.tokenize(words + '\n')[0][1]) == 32


def test_eof_without_newline_and_single_word():
    assert nu.tokenize('SHUTDOWNCMD /x') == [(1, ['SHUTDOWNCMD', '/x'], False)]
    assert nu.tokenize('LONELY') == []


def test_message_template_analysis():
    text = SAMPLE + ('NOTIFYCMD /n\nNOTIFYFLAG ONBATT EXEC\nNOTIFYFLAG ONLINE EXEC\n'
                     'NOTIFYMSG ONBATT "on battery $(id)"\nNOTIFYMSG ONLINE "UPS %d %s"\n')
    r = run(text)
    onbatt = event(r, 'ONBATT')
    assert onbatt['message_source'] == 'config' and onbatt['message']['shell_active']
    assert not onbatt['message']['includes_ups_name'] and onbatt['status'] == 'runs'
    online = event(r, 'ONLINE')
    assert online['status'] == 'unresolved' and not r['complete']
    assert cmd(r, 'NOTIFYCMD')['events'] == ['ONLINE', 'ONBATT']
    assert '$(id)' not in repr(r)


def test_debug_min_is_case_insensitive():
    r = run(SAMPLE + 'debug_min 1\n')
    assert r['line_notes'] == []


def test_fail_closed_inputs():
    assert 'config_not_observed' in run(None)['gaps'] and not run(None)['complete']
    assert 'argv_not_observed' in run(argv=None)['gaps']
    assert 'environment_not_observed' in run(env=None)['gaps']
    assert 'config_nul' in run(SAMPLE + '\x00')['gaps']
    assert 'config_too_large' in run('#' * (nu.MAX_TEXT + 1))['gaps']
    assert 'config_invalid' in run('\ud800')['gaps']
    assert 'argv_invalid' in run(argv=['-F\x00'])['gaps']
    assert 'argv_too_large' in run(argv=['-F'] * (nu.MAX_ARGV + 1))['gaps']
    assert 'default_user_invalid' in run(default_user='')['gaps']
    for argv in (['-c', 'fsd'], ['-K'], ['-h'], ['-V'], ['-i'], ['-x'], ['-u']):
        r = run(argv=argv)
        assert 'argv_exits' in r['gaps'] and not r['complete'], argv


def test_config_path_follows_f_and_nut_confpath():
    assert 'config_path_mismatch' in run(path='/etc/upsmon.conf')['gaps']
    assert run(argv=['-F', '-f', '/opt/u.conf'], path='/opt/u.conf')['complete']
    assert run(env={'NUT_CONFPATH': '/srv/nut'}, path='/srv/nut/upsmon.conf')['complete']
    assert 'config_path_mismatch' in run(env={'NUT_CONFPATH': '/srv/nut'})['gaps']
    # '+' in the optstring: getopt stops at the first operand.
    r = run(argv=['-F', 'extra', '-p'])
    assert r['mode'] == 'split' and r['complete']


def test_fingerprint_is_stable_and_input_sensitive():
    assert run()['fingerprint'] == run()['fingerprint']
    assert run()['fingerprint'] != run(SAMPLE + 'NOTIFYCMD /n\n')['fingerprint']
