from app import zabbix_user_parameters as z

MAIN = z.DEFAULT_CONFIG
DIR = '/etc/zabbix/zabbix_agentd.conf.d'


def run(main, extra=None, directories=None, absent=()):
    files = {MAIN: main}
    files.update(extra or {})
    return z.assess(files, directories or {}, absent)


def test_debian_layout_include_glob_in_readdir_order():
    result = run(
        'Server=127.0.0.1\nInclude=/etc/zabbix/zabbix_agentd.conf.d/*.conf\n',
        {DIR + '/b.conf': 'UserParameter=b.check,/usr/local/bin/b\n',
         DIR + '/a.conf': '  UserParameter=a.check[*],echo $1 $2,x\n',
         DIR + '/notes.txt': 'UserParameter=ignored,id\n'},
        {DIR: ['b.conf', 'notes.txt', 'a.conf']})
    assert result['status'] == 'complete' and result['complete']
    keys = [(p['item_key'], p['flexible'], p['command'], p['runs']) for p in result['user_parameters']]
    assert keys == [('b.check', False, '/usr/local/bin/b', True),
                    ('a.check', True, 'echo $1 $2,x', True)]
    flexible = result['user_parameters'][1]
    assert flexible['argv'] == ['/bin/sh', '-c', 'echo $1 $2,x']
    assert flexible['positional_parameters'] == [1, 2]
    assert flexible['unsafe_parameters_allowed'] is False
    assert flexible['source'] == DIR + '/a.conf' and flexible['line'] == 1
    assert result['run_as']['when_started_as_root'] == 'zabbix'
    assert result['remote_commands']['system_run'] == 'denied'
    assert result['origin'] == 'not_assessed' and result['verdict'] is None


def test_allow_root_user_and_last_value_wins():
    result = run('User=first\nUser=monitor\nAllowRoot=1\nUnsafeUserParameters=1\n'
                 'UserParameterDir=/opt/zbx\nUserParameter=x[*],cat $1\n')
    assert result['run_as']['when_started_as_root'] == 'root'
    assert result['run_as']['user'] == 'monitor'
    assert result['run_as']['user_source']['line'] == 2
    entry = result['user_parameters'][0]
    assert entry['cwd'] == '/opt/zbx' and entry['unsafe_parameters_allowed'] is True


def test_comments_trimming_and_exact_case_names():
    result = run('# UserParameter=commented,id\n\t userparameter=lower,id\nUserParameter =spaced,id \r\n')
    assert [p['key'] for p in result['user_parameters']] == ['spaced']
    assert result['user_parameters'][0]['command'] == 'id'


def test_startup_refusals_are_config_errors():
    cases = {
        'UserParameter=nocomma\n': 'user_parameter_not_comma_separated',
        'UserParameter= lead,id\nUserParameter=a b,id\n': 'user_parameter_key_syntax',
        'UserParameter=k[x],id\n': 'user_parameter_key_syntax',
        'UserParameter=k,id\nUserParameter=k[*],id\n': 'user_parameter_duplicate_key',
        'AllowRoot=2\n': 'wrong_value',
        'AllowRoot=1K\n': 'wrong_value',
        'EnableRemoteCommands=yes\n': 'wrong_value',
        'novalue\n': 'not_key_value',
        'Include=/etc/zabbix/*/x.conf\n': 'invalid_include',
        'Include=*.conf\n': 'invalid_include',
        'x=' + 'a' * 2047 + '\n': 'line_too_long',
    }
    for text, code in cases.items():
        result = run(text + 'UserParameter=other.key,id\n')
        assert result['status'] == 'config_error', text
        assert result['config_error']['code'] == code, text
        assert not any(p['runs'] for p in result['user_parameters']), text
        assert result['remote_commands']['system_run'] == 'agent_refuses_to_start'


def test_line_length_boundary_and_cr():
    assert run('x=' + 'a' * 2046 + '\n')['status'] == 'complete'
    assert run('x=' + 'a' * 2046 + '\r\n')['status'] == 'complete'


def test_include_missing_and_not_directory_stop_the_agent():
    missing = run('Include=/etc/zabbix/extra.conf\n', absent=['/etc/zabbix/extra.conf'])
    assert missing['config_error']['code'] == 'include_missing'
    not_dir = run('Include=/etc/zabbix/file/*.conf\n', {'/etc/zabbix/file': 'x=1\n'})
    assert not_dir['config_error']['code'] == 'include_base_not_directory'
    no_main = z.assess({}, {}, [MAIN])
    assert no_main['config_error']['code'] == 'cannot_open'


def test_include_recursion_stops_the_agent():
    result = run('Include=/etc/zabbix/loop.conf\n', {'/etc/zabbix/loop.conf': 'Include=/etc/zabbix/loop.conf\n'})
    assert result['config_error']['code'] == 'include_recursion'


def test_directory_include_reads_every_regular_file_and_trailing_slash():
    result = run('Include=/etc/zabbix/d/\n', {'/etc/zabbix/d/one': 'UserParameter=one,id\n'},
                 {'/etc/zabbix/d': ['one']})
    assert [p['key'] for p in result['user_parameters']] == ['one']
    plain = run('Include=/etc/zabbix/d\n', {'/etc/zabbix/d/one': 'UserParameter=one,id\n'},
                {'/etc/zabbix/d': ['one']})
    assert plain['user_parameters'][0]['runs'] is True


def test_unobserved_inputs_fail_closed_but_later_refusals_still_reported():
    gap = run('Include=/etc/zabbix/other.conf\nUserParameter=k,id\n')
    assert gap['status'] == 'incomplete' and gap['gaps'] == ['unobserved_file']
    listing = run('Include=%s/*.conf\n' % DIR, directories={DIR: None})
    assert listing['status'] == 'incomplete' and listing['gaps'] == ['unobserved_directory']
    relative = run('Include=conf.d/*.conf\n')
    assert relative['gaps'] == ['relative_include']
    later = run('Include=/etc/zabbix/other.conf\nAllowRoot=9\n')
    assert later['status'] == 'config_error'
    assert run(b'UserParameter=k,\xff\n')['gaps'] == ['invalid_utf8']
    assert run('UserParameter=k,id\0\n')['gaps'] == ['nul_byte']


def test_remote_command_rules_over_report():
    assert run('EnableRemoteCommands=1\n')['remote_commands']['system_run'] == 'possible'
    assert run('AllowKey=system.run[/usr/bin/uptime]\n')['remote_commands']['system_run'] == 'possible'
    assert run('AllowKey=*\n')['remote_commands']['system_run'] == 'possible'
    assert run('AllowKey=vfs.*\nDenyKey=system.run[*]\n')['remote_commands']['system_run'] == 'denied'


def test_match_glob_port():
    assert z.match_glob('a.conf', '*.conf')
    assert z.match_glob('.conf', '*.conf')
    assert not z.match_glob('a.conf.bak', '*.conf')
    assert z.match_glob('pa.conf', 'p*.conf')
    assert not z.match_glob('a.conf', 'p*')
    assert z.match_glob('xabyb', '*a*b')
    assert z.match_glob('anything', '*')


def test_fingerprint_is_stable():
    assert run('UserParameter=k,id\n')['fingerprint'] == run('UserParameter=k,id\n')['fingerprint']
