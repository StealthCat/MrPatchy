"""Tests for the pure openbsd-inetd /etc/inetd.conf contract (#1114).

Expected outcomes follow inetd.c in openbsd-inetd 0.20221205 with the Debian
0.20221205-3build5 patches applied (getconfigent, skip, nextline, config,
matchconf and spawn).
"""
from app import inetd_conf as ic


def run(text, **kw):
    return ic.evaluate(text, **kw)


def services(result):
    return [(s['service'], s['protocol'], s['host']) for s in result['services']]


def find(result, service, protocol):
    return next(s for s in result['services'] if s['service'] == service and s['protocol'] == protocol)


def codes(result):
    return [g['code'] for g in result['gaps']]


def test_root_shell_backdoor_loads_for_ipv4_and_ipv6_as_root():
    result = run('31337 stream tcp nowait root /bin/sh sh -i\n')
    assert result['complete'] and result['inetd_starts'] and not result['gaps']
    assert services(result) == [('31337', 'tcp', '*'), ('31337', 'tcp6', '*')]
    v4, v6 = result['services']
    assert v4['port'] == 31337 and v4['address'] == '0.0.0.0' and v6['address'] == '::'
    assert v4['program'] == '/bin/sh' and v4['argv'] == ['sh', '-i'] and v4['runs_as_root'] is True
    assert not v4['wait'] and v4['max'] is None and v4['max_default'] == 256
    assert v6['ipv6_copy'] and v6['requires_kernel_ipv6'] and not v4['requires_kernel_ipv6']
    assert v4['status'] == 'listens' and v4['origin'] == 'not_assessed' and result['origin'] == 'not_assessed'


def test_builtins_run_inside_inetd_and_ignore_wait():
    result = run('echo stream tcp4 wait root internal\nchargen dgram udp4 nowait nobody internal\n'
                 'echo raw tcp4 nowait root internal\nfinger stream tcp4 nowait root internal\n')
    echo = find(result, 'echo', 'tcp4')
    assert echo['builtin'] == 'echo' and echo['builtin_forks'] and not echo['wait']
    assert echo['program'] is None and echo['argv'] == [] and echo['runs_as_root'] is True
    assert find(result, 'chargen', 'udp4')['builtin_forks'] is False
    assert [(r['line'], r['reason']) for r in result['rejected']] == [
        (3, 'unknown_internal_service'), (4, 'unknown_internal_service')]
    # Name lookups are listed, not resolved.
    assert echo['lookups'] == [{'kind': 'service', 'name': 'echo', 'protocol': 'tcp'}]
    assert result['complete'] and set(codes(result)) == {'lookup_not_observed'}


def test_only_unindented_hash_starts_a_comment():
    result = run('#31337 stream tcp4 nowait root /bin/sh sh\n'
                 ' #x stream tcp4 nowait root /bin/sh sh\n')
    assert services(result) == [('#x', 'tcp4', '*')]
    assert find(result, '#x', 'tcp4')['lines'] == [2]


def test_indented_lines_continue_the_entry_and_a_blank_line_does_not_stop_it():
    result = run('2000 stream tcp4 nowait\n  root /bin/sh\n\tsh -i\n\n  2001 stream tcp4\n nowait root /bin/x\n'
                 'next\n')
    first = find(result, '2000', 'tcp4')
    assert first['user'] == 'root' and first['argv'] == ['sh', '-i'] and first['continued']
    # The blank line starts the next entry, and the indented line after it continues that entry.
    second = find(result, '2001', 'tcp4')
    assert second['program'] == '/bin/x' and second['argv'] == ['x'] and second['lines'] == [4]
    assert [(r['line'], r['reason']) for r in result['rejected']] == [(7, 'syntax_error')]


def test_ipv6_copy_reparses_only_the_first_physical_line():
    result = run('3000 stream tcp nowait root /bin/sh sh\n  -i\n3001 stream tcp nowait\n  root /bin/sh\n')
    assert find(result, '3000', 'tcp')['argv'] == ['sh', '-i']
    assert find(result, '3000', 'tcp6')['argv'] == ['sh']
    assert find(result, '3001', 'tcp')['program'] == '/bin/sh'
    assert ('3001', 'tcp6', '*') not in services(result)
    assert {'line': 3, 'service': '3001', 'protocol': 'tcp6', 'ipv6_copy': True,
            'reason': 'syntax_error'} in result['rejected']
    assert result['complete']


def test_ipv6_reparse_that_never_reaches_the_protocol_fails_closed():
    result = run('echo1 stream tcp4 nowait root /bin/a\n4000 stream\n  tcp nowait root /bin/sh sh\n')
    assert services(result) == [('echo1', 'tcp4', '*'), ('4000', 'tcp', '*')]
    assert 'reparse_never_ends' in codes(result) and not result['complete']


def test_ipv6_reparse_sees_the_nul_bytes_an_earlier_reparse_left_in_saved_line():
    # Re-parse 1 cuts saved_line to "40001\0stream" and fails on "tcp,x"; goto more re-parses only "40001",
    # which then takes the next continuation line and loads an IPv6 root shell.
    result = run('40001 stream\n\ttcp nowait root internal\n\ttcp,x\n\tstream tcp nowait root /bin/sh\n')
    shell = find(result, '40001', 'tcp6')
    assert (shell['user'], shell['program'], shell['argv']) == ('root', '/bin/sh', ['sh'])
    assert shell['runs_as_root'] is True
    assert {'line': 1, 'service': '40001', 'protocol': 'tcp', 'ipv6_copy': False,
            'reason': 'unknown_internal_service'} in result['rejected']
    assert result['complete']


def test_ipv6_reparse_cuts_saved_line_at_the_host_delimiter():
    # The host parser writes NUL at the last ':' (and at ']' for "[addr]:"), so the second re-parse of the
    # same entry reads "lo" or "[::1" as the whole first field.
    tail = '\n\ttcp nowait root internal\n\ttcp,x\n\tstream tcp nowait root /bin/sh\n'
    named = run('lo:40002 stream' + tail)
    assert services(named) == [('lo', 'tcp6', '*')]
    assert find(named, 'lo', 'tcp6')['program'] == '/bin/sh'
    bracketed = run('[::1]:40002 stream' + tail)
    assert services(bracketed) == [('1', 'tcp6', '[:')]
    assert ('40002', 'tcp6', '::1') not in services(bracketed)


def test_default_host_lines_brackets_and_host_lists():
    text = ('127.0.0.1:\n5000 stream tcp4 nowait root /bin/a\n[::1]:5001 stream tcp6 nowait root /bin/b\n'
            ':5002 stream tcp4 nowait root /bin/c\n10.0.0.1,,127.0.0.2:5003 stream tcp4 nowait root /bin/d\n'
            '::1:5004 stream tcp nowait root /bin/e\nexample.test:5005 stream tcp4 nowait root /bin/f\n')
    result = run(text)
    assert result['default_hosts'] == [{'line': 1, 'host': '127.0.0.1'}]
    assert find(result, '5000', 'tcp4')['address'] == '127.0.0.1'
    assert find(result, '5001', 'tcp6')['address'] == '::1'
    assert find(result, '5002', 'tcp4')['host'] == '*'
    assert [s['address'] for s in result['services'] if s['service'] == '5003'] == ['10.0.0.1', '127.0.0.2']
    # An IPv6 literal fails getaddrinfo() for the IPv4 copy but loads for the IPv6 copy.
    assert [s['protocol'] for s in result['services'] if s['service'] == '5004'] == ['tcp6']
    assert {'line': 6, 'service': '5004', 'protocol': 'tcp', 'ipv6_copy': False,
            'reason': 'no_resolvable_address'} in result['rejected']
    assert find(result, '5005', 'tcp4')['lookups'] == [{'kind': 'host', 'name': 'example.test'}]


def test_wait_mode_rate_limit_user_and_group():
    result = run('6000 stream tcp4 wait.10 nobody:nogroup /bin/a\n6001 stream tcp4 Wait.0x20 www-data.adm /bin/b\n'
                 '6002 stream tcp4 nowait.0 root.wheel /bin/c\n6003 dgram udp4 nowait.5x root /bin/d\n')
    a, b, c, d = result['services']
    assert a['wait'] and a['max'] == 10 and a['user'] == 'nobody' and a['group'] == 'nogroup'
    assert a['group_applied'] and a['runs_as_root'] is None
    assert not b['wait'] and b['max'] == 32 and b['group'] == 'adm'
    # A root user's group is ignored at spawn time; root's primary group is used.
    assert c['max'] is None and c['max_field_invalid'] and c['group'] == 'wheel' and c['group_applied'] is False
    assert d['max'] is None and d['max_field_invalid']


def test_argv_is_capped_at_twenty_and_defaults_to_the_base_name():
    args = ' '.join(f'a{i}' for i in range(25))
    result = run(f'7000 stream tcp4 nowait root /usr/bin/prog {args}\n7001 stream tcp4 nowait root bin/rel\n')
    capped = find(result, '7000', 'tcp4')
    assert capped['argv'] == [f'a{i}' for i in range(20)] and capped['argv_dropped'] == 5
    relative = find(result, '7001', 'tcp4')
    assert relative['argv'] == ['rel'] and relative['program_relative'] and not capped['program_relative']


def test_duplicate_entries_merge_as_config_does():
    result = run('8000 stream tcp4 nowait root /bin/a\n8000 stream tcp4 wait nobody /bin/b x\n'
                 'echo stream tcp4 nowait root internal\necho stream tcp4 nowait root /bin/evil e\n'
                 '8001 stream tcp4 wait root /bin/c\n8001 stream tcp4 nowait root /bin/d\n')
    merged = find(result, '8000', 'tcp4')
    # nowait then wait: the later wait is not taken.
    assert merged['lines'] == [1, 2] and not merged['wait'] and merged['user'] == 'nobody'
    assert merged['program'] == '/bin/b' and merged['argv'] == ['x']
    echo = find(result, 'echo', 'tcp4')
    assert echo['builtin'] == 'echo' and echo['program'] is None and echo['user'] == 'root'
    assert not find(result, '8001', 'tcp4')['wait']
    assert len(result['services']) == 3


def test_buffer_size_options():
    result = run('9000 stream tcp4,rcvbuf=64k nowait root /bin/a\n9001 stream tcp4,sndbuf=1k,rcvbuf=2k nowait root /bin/b\n'
                 '9002 stream tcp4,sndbuf=1024,rcvbuf=2k nowait root /bin/c\n9003 stream tcp4,a=1,b=2,c=3 nowait root /bin/d\n'
                 '9004 stream tcp4,bogus=1k nowait root /bin/e\n9005 stream tcp4,sndbuf=0k nowait root /bin/f\n')
    assert find(result, '9000', 'tcp4')['buffers'] == {'rcvbuf': 65536}
    assert find(result, '9001', 'tcp4')['buffers'] == {'sndbuf': 1024, 'rcvbuf': 2048}
    assert [(r['line'], r['reason']) for r in result['rejected']] == [
        (3, 'malformed_buffer_option'), (4, 'too_many_buffer_sizes'), (5, 'malformed_buffer_option'),
        (6, 'invalid_buffer_size')]
    assert result['complete']
    # A digits-only last size makes inetd read past the string: undefined, so fail closed.
    undefined = run('9006 stream tcp4,rcvbuf=65536 nowait root /bin/sh sh\n')
    assert find(undefined, '9006', 'tcp4')['status'] == 'unresolved'
    assert 'buffer_size_undefined' in codes(undefined) and not undefined['complete']


def test_rpc_unix_and_unknown_socket_types():
    result = run('rstatd/1-3 dgram rpc/udp wait root /usr/sbin/rpc.rstatd\n300/1 dgram rpc/udp4 wait root /bin/w\n'
                 '100008/2 dgram rpc/udp4 wait root /bin/v\n'
                 'mountd/x dgram rpc/udp4 wait root /bin/m\nnfs dgram rpc/udp4 wait root /bin/n\n'
                 '/run/x.sock stream unix nowait root /bin/u\n'
                 f'/{"p" * 120} stream unix nowait root /bin/long\n9100 seqpacket tcp4 nowait root /bin/q\n')
    rstat = find(result, 'rstatd', 'rpc/udp')
    assert rstat['rpc'] == {'versions': [1, 3], 'program': None}
    assert {'kind': 'rpc', 'name': 'rstatd'} in rstat['lookups']
    assert find(result, 'rstatd', 'rpc/udp6')['ipv6_copy']
    assert find(result, '300', 'rpc/udp4')['rpc'] == {'versions': [1, 1], 'program': 300}
    # strtonum(service, 1, USHRT_MAX) rejects larger numbers, so they need a getrpcbyname() lookup.
    assert find(result, '100008', 'rpc/udp4')['lookups'] == [{'kind': 'rpc', 'name': '100008'}]
    assert [(r['line'], r['reason']) for r in result['rejected']] == [(4, 'bad_rpc_version'), (5, 'no_rpc_version')]
    unix = find(result, '/run/x.sock', 'unix')
    assert unix['unix_path'] == '/run/x.sock' and unix['status'] == 'listens' and unix['family'] == 'unix'
    long = next(s for s in result['services'] if s['program'] == '/bin/long')
    assert (long['status'], long['reason']) == ('never_listens', 'unix_path_too_long')
    assert (find(result, '9100', 'tcp4')['status'], find(result, '9100', 'tcp4')['reason']) == (
        'never_listens', 'unknown_socket_type')


def test_service_lookup_protocol_name_per_family():
    result = run('ssh stream tcp nowait root /bin/a\nntp dgram udp46 wait root /bin/b\n')
    assert find(result, 'ssh', 'tcp')['lookups'] == [{'kind': 'service', 'name': 'ssh', 'protocol': 'tcp'}]
    assert find(result, 'ssh', 'tcp6')['lookups'] == [{'kind': 'service', 'name': 'ssh', 'protocol': 'tcp'}]
    # IPv6 strips only one trailing digit.
    assert find(result, 'ntp', 'udp46')['lookups'][0]['protocol'] == 'udp4'


def test_long_lines_are_read_in_1023_byte_pieces():
    filler = 'x' * (1023 - len('9200 stream tcp4 nowait root /bin/a '))
    result = run(f'9200 stream tcp4 nowait root /bin/a {filler}9201 stream tcp4 nowait root /bin/b\n')
    assert find(result, '9200', 'tcp4')['argv'] == [filler]
    assert find(result, '9201', 'tcp4')['lines'] == [2]


def test_fail_closed_inputs():
    absent = run(None, state='absent')
    assert absent['complete'] and absent['inetd_starts'] is False and absent['services'] == []
    for result, code in ((run(None), 'text_not_observed'), (run(None, state='unreadable'), 'file_unreadable'),
                         (run(b'a\x00b'), 'binary'), (run(b'\xff\n'), 'invalid_utf8'),
                         (run('#' * (ic.MAX_TEXT + 1)), 'over_limit')):
        assert not result['complete'] and codes(result) == [code] and result['inetd_starts'] is None
    assert any('Name lookups' in note for note in absent['not_observed'])
