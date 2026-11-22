"""Tests for the pure NRPE command contract (#1335).

Expected outcomes are derived from nrpe 4.1.0 ``src/nrpe.c`` (read_config_file,
read_config_dir, add_command, find_command, process_macros, my_system, drop_privileges).
"""
from __future__ import annotations

from app import nrpe_commands as nc

MAIN = '/etc/nagios/nrpe.cfg'
DAEMON = {'mode': 'daemon', 'start_user': 'root'}
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
    assert users['user'] == 'nagios' and users['group'] == 'nagios' and users['fallback_user'] == 'root'
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
    result = run(main)
    commands = by_name(result)
    assert commands[' spaced ']['command_line'] == '/usr/bin/sudo  /bin/a'
    assert commands['x']['command_line'] == '/usr/bin/sudo =/bin/b'
    assert commands['y']['command_line'] == '/usr/bin/sudo /bin/c'
    assert commands['z']['command_line'] == '/usr/bin/sudo /bin/d'
    assert 'comment' not in commands
    assert commands['x']['user'] == 'root' and commands['x']['prefixed']


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
    result = run(f'command[x]={value}command[y]=/bin/y\n')
    commands = by_name(result)
    assert commands['x']['command_line'] == value and commands['y']['command_line'] == '/bin/y'


def test_arguments_and_inetd_account():
    main = 'dont_blame_nrpe=1\nallow_bash_command_substitution=1\nnrpe_user=nagios\ncommand[a]=/bin/a $ARG1$ $ARG17$\n'
    result = run(main, daemon={'mode': 'inetd', 'start_user': 'nagios-inetd'})
    command = by_name(result)['a']
    assert command['arguments_accepted'] and command['argument_macros'] == [1]
    assert command['user'] == 'nagios-inetd' and command['fallback_user'] is None
    assert result['bash_command_substitution']


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
