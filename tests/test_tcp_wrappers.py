import pytest

from app import tcp_wrappers as tw


def _obs(allow=None, deny=None, allow_state=None, deny_state=None):
    def one(text, state):
        if state:
            return {'state': state}
        return {'state': 'absent'} if text is None else {'state': 'regular', 'text': text}
    return {'hosts_allow': one(allow, allow_state), 'hosts_deny': one(deny, deny_state)}


def _cmds(result):
    return [(c['path'], c['line'], c['option'], c['command'], c['reachable']) for c in result['commands']]


def test_spawn_twist_and_aclexec_are_reported_with_effects():
    allow = ('sshd : 10.0.0.0/8 : spawn (/usr/bin/logger %h %u) &\n'
             'in.telnetd : ALL : aclexec /usr/local/bin/check %a : twist /bin/echo no\n')
    result = tw.resolve(_obs(allow))
    assert result['complete'] and not result['authorizes_response']
    first, second, third = result['commands']
    assert first['option'] == 'spawn' and first['command'] == '(/usr/bin/logger %h %u) &'
    assert first['argv'] == ['/bin/sh', '-c', '(/usr/bin/logger %h %u) &']
    assert first['expansions'] == ['%h', '%u'] and first['daemons'] == ['sshd']
    assert first['effect'] == 'forked_shell_waited_stdio_dev_null'
    assert second['option'] == 'aclexec' and second['after_runtime_checks'] == []
    assert third['option'] == 'twist' and third['after_runtime_checks'] == ['aclexec']
    assert third['effect'] == 'replaces_daemon_with_shell_client_socket_stdio'
    assert all(c['runs_as'] == 'daemon_process_user' for c in result['commands'])
    assert result['reachable_commands'] == 3


def test_user_and_group_options_do_not_change_identity_in_the_debian_build():
    result = tw.resolve(_obs('ALL : ALL : user nobody.nogroup : group adm : spawn /tmp/x\n'))
    command, = result['commands']
    assert command['runs_as'] == 'daemon_process_user'
    assert command['identity_options_ignored'] == [
        {'option': 'user', 'value': 'nobody.nogroup'}, {'option': 'group', 'value': 'adm'}]
    assert command['after_runtime_checks'] == ['user', 'group']


def test_option_error_aborts_later_options_but_earlier_spawn_already_ran():
    result = tw.resolve(_obs('ALL : ALL : spawn /tmp/a : bogus : spawn /tmp/b\n'))
    entry = result['tables'][0]['entries'][0]
    assert entry['option_error'] == {'index': 1, 'option': 'bogus', 'reason': 'bad_option_name'}
    assert [c['command'] for c in result['commands']] == ['/tmp/a']


@pytest.mark.parametrize('options, reason', [
    ('spawn', 'option_requires_value'),
    ('keepalive yes', 'option_requires_no_value'),
    ('twist /bin/x : spawn /tmp/y', 'option_must_be_at_end'),
    ('allow : spawn /tmp/y', 'option_must_be_at_end'),
    ('spawn /tmp/y :', 'missing_option_name'),  # the kept newline is an empty field
    ('spawn /tmp/y', None),
    ('spawn /tmp/y : ', 'missing_option_name'),
])
def test_option_errors(options, reason):
    result = tw.resolve(_obs(f'sshd : ALL : {options}\n'))
    error = result['tables'][0]['entries'][0]['option_error']
    assert (error and error['reason']) == reason


def test_keywords_are_case_insensitive_and_equals_is_accepted():
    result = tw.resolve(_obs('ALL : ALL : SpAwN = /tmp/x\n'))
    assert _cmds(result) == [('/etc/hosts.allow', 1, 'spawn', '/tmp/x', True)]


def test_escaped_colon_stays_in_the_command():
    result = tw.resolve(_obs('ALL : ALL : spawn echo a\\:b > /tmp/log\n'))
    assert result['commands'][0]['command'] == 'echo a:b > /tmp/log'


def test_bracketed_ipv6_client_does_not_split_fields():
    result = tw.resolve(_obs('sshd : [::1]/128 : spawn /tmp/x\n'))
    entry = result['tables'][0]['entries'][0]
    assert entry['clients'] == ['[::1]/128'] and result['commands'][0]['command'] == '/tmp/x'


def test_comments_only_in_column_zero_and_missing_separator_is_skipped():
    allow = '# ALL : ALL : spawn /tmp/c\n   \nnot an entry\n  # x : y : spawn /tmp/d\n'
    result = tw.resolve(_obs(allow))
    table = result['tables'][0]
    assert table['skipped'] == [{'line': 3, 'reason': 'missing_separator'}]
    assert _cmds(result) == [('/etc/hosts.allow', 4, 'spawn', '/tmp/d', True)]
    assert table['entries'][0]['daemons'] == ['#', 'x']


def test_backslash_newline_continues_an_entry():
    result = tw.resolve(_obs('sshd : ALL : \\\n spawn /tmp/x\nother : ALL : spawn /tmp/y\n'))
    assert [(c['line'], c['command']) for c in result['commands']] == [(1, '/tmp/x'), (3, '/tmp/y')]


def test_missing_final_newline_and_long_lines_stop_the_file():
    result = tw.resolve(_obs('a : ALL : spawn /tmp/1\nb : ALL : spawn /tmp/2'))
    assert result['tables'][0]['error'] == {'code': 'missing_newline_or_line_too_long', 'line': 2}
    assert [c['command'] for c in result['commands']] == ['/tmp/1']
    fits = 'a : ALL : spawn ' + 'x' * (tw.BUFLEN - 1 - len('a : ALL : spawn ') - 1) + '\n'
    assert len(fits) == tw.BUFLEN - 1
    assert len(tw.resolve(_obs(fits))['commands']) == 1
    too_long = fits[:-1] + 'y\nb : ALL : spawn /tmp/2\n'
    result = tw.resolve(_obs(too_long))
    assert result['commands'] == [] and result['tables'][0]['error']['line'] == 1


def test_continuation_counts_against_the_logical_buffer():
    head = 'a : ALL : spawn ' + 'x' * 1500 + '\\\n'
    result = tw.resolve(_obs(head + 'y' * 600 + '\n'))
    assert result['tables'][0]['error'] is not None
    result = tw.resolve(_obs(head + 'y' * 400 + '\n'))
    assert result['tables'][0]['error'] is None and len(result['commands']) == 1


def test_unconditional_entry_shadows_later_entries_and_hosts_deny():
    allow = 'ALL : ALL\nsshd : ALL : spawn /tmp/late\n'
    result = tw.resolve(_obs(allow, 'ALL : ALL : spawn /tmp/deny\n'))
    assert _cmds(result) == [('/etc/hosts.allow', 2, 'spawn', '/tmp/late', False),
                             ('/etc/hosts.deny', 1, 'spawn', '/tmp/deny', False)]
    assert result['commands'][1]['shadowed_by'] == {'path': '/etc/hosts.allow', 'line': 1}
    assert result['reachable_commands'] == 0


def test_aclexec_unconditional_allow_does_not_shadow_hosts_deny():
    result = tw.resolve(_obs('all : all : aclexec /bin/false\n', 'ALL : ALL : spawn /tmp/d\n'))
    assert [c['reachable'] for c in result['commands']] == [True, True]


@pytest.mark.parametrize('allow', [
    'ALL EXCEPT sshd : ALL\n', 'ALL : ALL EXCEPT 10.\n', '* : ALL\n', 'ALL@host : ALL\n',
    'sshd : ALL\n',
])
def test_conditional_entries_never_shadow(allow):
    result = tw.resolve(_obs(allow + 'sshd : ALL : spawn /tmp/x\n', 'ALL : ALL : spawn /tmp/d\n'))
    assert [c['reachable'] for c in result['commands']] == [True, True]


def test_unrecognized_expansions_are_reported():
    result = tw.resolve(_obs('ALL : ALL : spawn echo %h %z %% %\n'))
    command = result['commands'][0]
    assert command['expansions'] == ['%h', '%%'] and command['unrecognized_expansions'] == ['%z']


def test_file_states():
    result = tw.resolve(_obs(allow_state='unreadable', deny='ALL : ALL : spawn /tmp/d\n'))
    assert result['complete'] and result['tables'][0]['error']['code'] == 'cannot_open'
    assert result['commands'][0]['reachable']
    result = tw.resolve({'hosts_deny': {'state': 'absent'}})
    assert not result['complete'] and result['gaps'] == [{'code': 'file_unobserved', 'path': '/etc/hosts.allow'}]
    result = tw.resolve(_obs(allow_state='not_regular'))
    assert result['gaps'][0]['code'] == 'file_not_modelled'
    result = tw.resolve(_obs('ALL : ALL : spawn /tmp/x\0\n'))
    assert result['gaps'][0]['code'] == 'nul_byte' and result['commands'] == []


@pytest.mark.parametrize('observation', [
    None, [], {'other': {}}, {'hosts_allow': {'state': 'weird'}},
    {'hosts_allow': {'state': 'regular'}}, {'hosts_allow': {'state': 'absent', 'text': ''}},
    {'hosts_allow': {'state': 'regular', 'text': 'x' * (tw.MAX_TEXT + 1)}},
])
def test_invalid_observations(observation):
    with pytest.raises(tw.Invalid):
        tw.resolve(observation)


def test_case_folding_is_ascii_only_like_strcasecmp():
    # U+212A KELVIN SIGN lowercases to "k" in Python but not in strcasecmp().
    result = tw.resolve(_obs('ALL : ALL : \u212aeepalive : spawn /tmp/x\n'))
    assert result['tables'][0]['entries'][0]['option_error']['reason'] == 'bad_option_name'
    assert result['commands'] == []
    result = tw.resolve(_obs('\u0130LL : ALL\nsshd : ALL : spawn /tmp/x\n'))
    assert result['commands'][0]['reachable']


def test_a_too_long_comment_line_still_stops_the_file():
    allow = '#' + 'x' * tw.BUFLEN + '\nALL : ALL : spawn /tmp/x\n'
    result = tw.resolve(_obs(allow, 'ALL : ALL : spawn /tmp/d\n'))
    assert result['tables'][0]['error'] == {'code': 'missing_newline_or_line_too_long', 'line': 1}
    assert _cmds(result) == [('/etc/hosts.deny', 1, 'spawn', '/tmp/d', True)]


def test_an_earlier_aclexec_keeps_hosts_deny_reachable():
    allow = 'in.telnetd : 192.0.2.1 : aclexec /bin/false\nALL : ALL : spawn /bin/log\n'
    result = tw.resolve(_obs(allow, 'ALL : ALL : spawn /bin/alert\n'))
    assert [c['reachable'] for c in result['commands']] == [True, True, True]


def test_line_length_is_counted_in_bytes():
    allow = 'ALL : ALL : spawn echo ' + '\u00e9' * 1100 + '\n'
    result = tw.resolve(_obs(allow, 'ALL : ALL : spawn /bin/alert\n'))
    assert result['tables'][0]['error']['code'] == 'missing_newline_or_line_too_long'
    assert _cmds(result) == [('/etc/hosts.deny', 1, 'spawn', '/bin/alert', True)]
    with pytest.raises(tw.Invalid):
        tw.resolve(_obs('ALL : ALL : spawn \ud800\n'))
