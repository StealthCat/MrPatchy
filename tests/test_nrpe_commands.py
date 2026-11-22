"""Tests for the pure NRPE command contract (#1335).

Expected outcomes are derived from nrpe 4.1.0 ``src/nrpe.c`` (read_config_file,
read_config_dir, add_command, find_command, process_macros, my_system, drop_privileges,
check_privileges).
"""
from __future__ import annotations

from app import nrpe_commands as nc

MAIN = '/etc/nagios/nrpe.cfg'
DAEMON = {'mode': 'daemon', 'start_user': 'root'}
NAGIOS = {'mode': 'daemon', 'start_user': 'nagios', 'start_group': 'nagios'}
DEBIAN = (
    'log_facility=daemon\n'
    'pid_file=/run/nagios/nrpe.pid\n'
    'server_port=5666\n'
    'nrpe_user=nagios\n'
    'nrpe_group=nagios\n'
    'allowed_hosts=127.0.0.1,::1\n'
    'dont_blame_nrpe=0\n'
    'command_timeout=60\n'
    'command[check_users]=/usr/lib/nagios/plugins/check_users -w 5 -c 10\n'
    'command[check_load]=/usr/lib/nagios/plugins/check_load -r -w .15,.10,.05 -c .30,.25,.20\n'
    'include=/etc/nagios/nrpe_local.cfg\n'
    'include_dir=/etc/nagios/nrpe.d/\n'
)


def run(main=DEBIAN, extra=None, dirs=None, daemon=DAEMON):
    files = {MAIN: main, '/etc/nagios/nrpe_local.cfg': ''}
    files.update(extra or {})
    return nc.evaluate(files, {'/etc/nagios/nrpe.d': []} if dirs is None else dirs, daemon=daemon)


def by_name(result):
    return {command['name']: command for command in result['commands']}


def test_debian_default_runs_two_commands_as_nagios():
    result = run()
    assert result['complete'] and result['starts'] is True
    commands = by_name(result)
    assert sorted(commands) == ['check_load', 'check_users']
    users = commands['check_users']
    assert users['command_line'] == '/usr/lib/nagios/plugins/check_users -w 5 -c 10'
    # Started as root, a failed nrpe_user lookup leaves root and check_privileges exits, so there is no fallback.
    assert users['user'] == 'nagios' and users['group'] == 'nagios' and users['fallback_user'] is None
    assert users['via'] == '/bin/sh -c' and users['line'] == 9 and not users['arguments_accepted']
    assert result['origin'] == 'not_assessed' and len(users['sha256']) == 64
    assert [entry['path'] for entry in result['files']] == [MAIN, '/etc/nagios/nrpe_local.cfg']


def test_last_definition_wins_across_include_dir_in_byte_order():
    dirs = {'/etc/nagios/nrpe.d': [{'name': 'b.cfg', 'type': 'file'}, {'name': 'A.cfg', 'type': 'file'},
                                   {'name': '.hidden.cfg', 'type': 'file'}, {'name': 'notes.txt', 'type': 'file'}]}
    extra = {'/etc/nagios/nrpe.d/A.cfg': 'command[check_users]=/bin/A\n',
             '/etc/nagios/nrpe.d/b.cfg': 'command[check_users]=/tmp/evil\n',
             '/etc/nagios/nrpe.d/.hidden.cfg': 'command[x]=/bin/hidden\n'}
    result = run(extra=extra, dirs=dirs)
    assert result['complete']
    assert [entry['path'] for entry in result['files']][2:] == [
        '/etc/nagios/nrpe.d/.hidden.cfg', '/etc/nagios/nrpe.d/A.cfg', '/etc/nagios/nrpe.d/b.cfg']
    users = by_name(result)['check_users']
    assert users['command_line'] == '/tmp/evil' and users['path'] == '/etc/nagios/nrpe.d/b.cfg'
    assert users['overrides'] == [{'path': MAIN, 'line': 9}, {'path': '/etc/nagios/nrpe.d/A.cfg', 'line': 1}]
    assert by_name(result)['x']['command_line'] == '/bin/hidden'


def test_subdirectory_recursion_skips_hidden_and_cfg_named_directories():
    dirs = {'/etc/nagios/nrpe.d': [{'name': 'sub', 'type': 'directory'}, {'name': '.git', 'type': 'directory'},
                                   {'name': 'dir.cfg', 'type': 'directory'}, {'name': 'fifo.cfg', 'type': 'other'}],
            '/etc/nagios/nrpe.d/sub': [{'name': 'deep.cfg', 'type': 'file'}]}
    result = run(extra={'/etc/nagios/nrpe.d/sub/deep.cfg': 'command[deep]=/bin/deep\n'}, dirs=dirs)
    assert result['complete'] and by_name(result)['deep']['command_line'] == '/bin/deep'


def test_name_and_value_follow_strtok():
    main = ('  command[ spaced ] = /bin/a\n'
            'command[x]==/bin/b\n'
            'xcommand[y]=/bin/c\n'
            'command[z=/bin/d\n'
            'nrpe_user = ignored\n'
            '# command[comment]=/bin/no\n'
            'command_prefix=/usr/bin/sudo\n')
    result = run(main, daemon=NAGIOS)
    commands = by_name(result)
    assert result['complete'] and result['starts'] is True
    assert commands[' spaced ']['command_line'] == '/usr/bin/sudo  /bin/a'
    assert commands['x']['command_line'] == '/usr/bin/sudo =/bin/b'
    assert commands['y']['command_line'] == '/usr/bin/sudo /bin/c'
    assert commands['z']['command_line'] == '/usr/bin/sudo /bin/d'
    assert 'comment' not in commands
    assert commands['x']['user'] == 'nagios' and commands['x']['group'] == 'nagios' and commands['x']['prefixed']


def test_main_file_error_refuses_start_and_lists_nothing():
    for bad in ('command[]=/bin/x\n', 'command[x]=\n', 'server_port=80\n', 'command_timeout=0\n',
                'ssl_version=TLSv9\n', 'just_a_name\n'):
        result = run('command[ok]=/bin/ok\n' + bad)
        assert result['starts'] is False and result['commands'] == [], bad
        assert result['files'][0]['error']['line'] == 2


def test_included_file_error_keeps_earlier_definitions_and_continues():
    extra = {'/etc/nagios/nrpe_local.cfg': 'command[kept]=/bin/kept\ncommand[]=/x\ncommand[lost]=/bin/lost\n'}
    result = run(extra=extra)
    commands = by_name(result)
    assert result['starts'] is True and result['complete']
    assert 'kept' in commands and 'lost' not in commands and 'check_users' in commands
    assert result['files'][1]['error']['line'] == 2


def test_overlong_line_is_split_like_fgets():
    value = 'a' * (nc.FGETS_CHUNK - len('command[x]='))
    result = run(f'command[x]={value}command[y]=/bin/y\n', daemon=NAGIOS)
    commands = by_name(result)
    assert commands['x']['command_line'] == value and commands['y']['command_line'] == '/bin/y'


def test_arguments_and_inetd_account():
    main = 'dont_blame_nrpe=1\nallow_bash_command_substitution=1\nnrpe_user=nagios\ncommand[a]=/bin/a $ARG1$ $ARG17$\n'
    result = run(main, daemon={'mode': 'inetd', 'start_user': 'nagios-inetd', 'start_group': 'nagios'})
    command = by_name(result)['a']
    assert command['arguments_accepted'] and command['argument_macros'] == [1]
    assert command['user'] == 'nagios-inetd' and command['group'] == 'nagios' and command['fallback_user'] is None
    assert result['bash_command_substitution'] and result['complete']


def test_blocking_gaps():
    unobserved = nc.evaluate({MAIN: DEBIAN}, {'/etc/nagios/nrpe.d': []}, daemon=DAEMON)
    assert not unobserved['complete'] and 'file_not_observed' in {gap['code'] for gap in unobserved['gaps']}
    assert not nc.evaluate({}, {}, daemon=DAEMON)['complete']
    relative = run('include=local.cfg\n')
    assert not relative['complete'] and relative['gaps'][0]['code'] == 'relative_include'
    cycle = run('include=/etc/nagios/nrpe.cfg\n')
    assert not cycle['complete'] and cycle['starts'] is None
    missing = run(dirs={'/etc/nagios/nrpe.d': [{'name': 'gone.cfg', 'type': 'missing'}]})
    assert not missing['complete'] and 'entry_stat_failed' in {gap['code'] for gap in missing['gaps']}
    no_daemon = run(daemon=None)
    assert not no_daemon['complete'] and by_name(no_daemon)['check_users']['user'] == 'nagios'
    unlisted = run(dirs={})
    assert not unlisted['complete']
    assert run('ssl_version=SSLv2\n')['complete'] is False


def test_absent_main_file_and_directory():
    assert nc.evaluate({MAIN: 'absent'}, {}, daemon=DAEMON)['starts'] is False
    result = run(dirs={'/etc/nagios/nrpe.d': 'absent'})
    assert result['complete'] and result['starts'] is True


def test_argument_macros_follow_process_macros_token_rule():
    # process_macros splits on '$' with my_strsep; a macro-position token starting with ARG
    # selects argument atoi(token + 3), so trailing text and leading white space still match.
    cases = {
        '/bin/c $ARG1x$': [1],
        '/bin/c $ARG 2$': [2],
        '/bin/c $ARG+3$ $ARG04$': [3, 4],
        '/bin/c $x$ARG1$': [],          # ARG1 lands in a literal position
        '/bin/c $$ARG1$': [],           # '$$' is an escaped '$', ARG1 is literal
        '/bin/c $ARG0$ $ARG17$ $ARG-1$ $ARG$': [],
        '/bin/c $ARG4294967297$': [1],  # (int)strtol truncation
        '/bin/c $ARG99999999999999999999$': [],  # saturates to LONG_MAX, which is -1 as int
        '/bin/c $ARG1$ $ARG16$': [1, 16],
    }
    main = 'nrpe_user=nagios\nnrpe_group=nagios\ndont_blame_nrpe=1\n' + ''.join(
        f'command[c{index}]={line}\n' for index, line in enumerate(cases))
    commands = by_name(run(main))
    for index, (line, expected) in enumerate(cases.items()):
        assert commands[f'c{index}']['argument_macros'] == expected, line


def test_root_after_privilege_drop_refuses_start():
    # set_stdio_sigs: drop_privileges then check_privileges, which exits if EUID or EGID is 0.
    refused = [
        ('command[x]=/bin/x\n', DAEMON),                                     # no nrpe_user: stays root
        ('nrpe_user=nagios\ncommand[x]=/bin/x\n', {**DAEMON, 'start_group': 'root'}),  # EGID stays 0
        ('nrpe_user=0\nnrpe_group=nagios\ncommand[x]=/bin/x\n', DAEMON),
        ('nrpe_user=root\nnrpe_group=nagios\ncommand[x]=/bin/x\n', NAGIOS),
        ('nrpe_user=nagios\nnrpe_group=00\ncommand[x]=/bin/x\n', DAEMON),
        ('command[x]=/bin/x\n', {'mode': 'inetd', 'start_user': 'root', 'start_group': 'nagios'}),
        ('command[x]=/bin/x\n', {'mode': 'inetd', 'start_user': 'nagios', 'start_group': '0'}),
    ]
    for main, daemon in refused:
        result = run(main, daemon=daemon)
        assert result['starts'] is False and result['commands'] == [], (main, daemon)
        assert result['complete'] and 'check_privileges' in result['refusal']
    # inetd never drops privileges, so nrpe_user/nrpe_group cannot rescue a root start.
    inetd = run('nrpe_user=nagios\nnrpe_group=nagios\ncommand[x]=/bin/x\n',
                daemon={'mode': 'inetd', 'start_user': 'root', 'start_group': 'root'})
    assert inetd['starts'] is False and inetd['commands'] == []


def test_unobserved_start_group_is_blocking_and_non_root_fallback_kept():
    result = run('nrpe_user=nagios\ncommand[x]=/bin/x\n', daemon={'mode': 'daemon', 'start_user': 'nagios'})
    assert not result['complete'] and 'start_group_not_observed' in {gap['code'] for gap in result['gaps']}
    assert by_name(result)['x']['user'] == 'nagios' and by_name(result)['x']['group'] is None
    kept = run('nrpe_user=other\nnrpe_group=other\ncommand[x]=/bin/x\n', daemon=NAGIOS)
    assert kept['complete'] and by_name(kept)['x']['fallback_user'] == 'nagios'
    assert not run(daemon={'mode': 'daemon', 'start_user': 'root', 'start_group': 7})['complete']


def test_prefixed_command_line_holds_one_byte_less():
    base = 'nrpe_user=nagios\nnrpe_group=nagios\n'
    plain = 'a' * nc.MAX_COMMAND_LINE
    unprefixed = by_name(run(base + f'command[x]={plain[:2000]}\n'))['x']
    assert not unprefixed['truncated']
    # A config line holds at most 2046 bytes (fgets), so use a long prefix: 1000 + 1 + 1046 = 2047 bytes.
    prefix, body = '/' + 'p' * 999, 'b' * 1046
    command = by_name(run(base + f'command_prefix={prefix}\ncommand[x]={body}\n'))['x']
    assert command['truncated'] and len(command['command_line']) == nc.MAX_PREFIXED_LINE == 2046
    assert command['command_line'] == f'{prefix} {body}'[:2046]
    fits = by_name(run(base + f'command_prefix={prefix}\ncommand[x]={body[:-1]}\n'))['x']
    assert not fits['truncated'] and len(fits['command_line']) == 2046
