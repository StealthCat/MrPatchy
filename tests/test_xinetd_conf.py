"""Tests for the pure xinetd configuration contract (issue #1122)."""

from app.xinetd_conf import resolve_xinetd

DEBIAN_MAIN = """# Simple configuration file for xinetd
defaults
{
# log_type = SYSLOG daemon info
}

includedir /etc/xinetd.d
"""

BACKDOOR = """service backdoor
{
    type        = UNLISTED
    socket_type = stream
    protocol    = tcp
    port        = 31337
    wait        = no
    user        = root
    server      = /bin/sh
    server_args = -i
}
"""


def _run(files, listing=None):
    directories = {'/etc/xinetd.d': listing} if listing is not None else {}
    return resolve_xinetd(files, directories)


def _svc(result, name):
    return next(s for s in result['services'] if s['name'] == name)


def test_unlisted_root_shell_from_includedir_is_reported():
    result = _run({'/etc/xinetd.conf': DEBIAN_MAIN, '/etc/xinetd.d/backdoor': BACKDOOR},
                  [('backdoor', 'file')])
    assert result['complete'] is True
    assert result['origin'] == 'not_assessed'
    svc = _svc(result, 'backdoor')
    assert svc['status'] == 'loads_if_lookups_succeed'
    assert svc['argv'] == ['sh', '-i']
    assert svc['server'] == '/bin/sh'
    assert svc['runs_as_root'] is True
    assert svc['port'] == '31337'
    assert result['root_services'] == ['backdoor']
    assert 'executable:/bin/sh' in svc['required_lookups']
    # UNLISTED services need no /etc/services lookup.
    assert not any(x.startswith('services:') for x in svc['required_lookups'])


def test_debian_shipped_disabled_internal_service_is_not_loaded():
    echo = """service echo
{
\tdisable\t\t= yes
\ttype\t\t= INTERNAL
\tid\t\t= echo-stream
\tsocket_type\t= stream
\tprotocol\t= tcp
\tuser\t\t= root
\twait\t\t= no
}
"""
    result = _run({'/etc/xinetd.conf': DEBIAN_MAIN, '/etc/xinetd.d/echo': echo},
                  [('echo', 'file')])
    assert result['services'] == []
    assert result['loaded_services'] == []
    assert result['dropped_entries'][0]['reason'] == 'disabled_at_disable_line'


def test_includedir_skips_dotted_and_tilde_names_and_sorts_bytewise():
    def body(port):
        return BACKDOOR.replace('backdoor', 'svc').replace('31337', port)
    files = {
        '/etc/xinetd.conf': DEBIAN_MAIN,
        '/etc/xinetd.d/b': body('2').replace('service svc', 'service b'),
        '/etc/xinetd.d/a': body('1').replace('service svc', 'service a'),
        '/etc/xinetd.d/Z': body('3').replace('service svc', 'service Z'),
        '/etc/xinetd.d/c.dpkg-old': body('4'),
        '/etc/xinetd.d/d~': body('5'),
    }
    listing = [('b', 'file'), ('a', 'file'), ('Z', 'file'), ('c.dpkg-old', 'file'),
               ('d~', 'file'), ('sub', 'directory')]
    result = _run(files, listing)
    assert result['files_read'] == ['/etc/xinetd.conf', '/etc/xinetd.d/Z',
                                    '/etc/xinetd.d/a', '/etc/xinetd.d/b']
    assert [s['name'] for s in result['services']] == ['Z', 'a', 'b']
    assert {'path': '/etc/xinetd.d/sub', 'reason': 'not_regular_file'} in result['dropped_entries']


def test_indented_hash_is_comment_but_inline_hash_is_a_value():
    text = BACKDOOR.replace('    server_args = -i', '    # server_args = -x\n    server_args = -i #x')
    result = _run({'/etc/xinetd.conf': text})
    assert _svc(result, 'backdoor')['argv'] == ['sh', '-i', '#x']


def test_first_value_wins_and_bad_operator_is_ignored():
    text = BACKDOOR.replace('    user        = root\n',
                            '    user        = nobody\n    user        = root\n'
                            '    server     += /bin/bash\n')
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'backdoor')
    assert svc['user'] == 'nobody'
    assert svc['runs_as_root'] is None
    reasons = {(i['attribute'], i['reason']) for i in svc['ignored_attributes']}
    assert ('user', 'already_set') in reasons
    assert ('server', 'operator_not_allowed') in reasons


def test_attribute_without_space_before_operator_drops_the_entry():
    text = BACKDOOR.replace('    wait        = no', '    wait= no')
    result = _run({'/etc/xinetd.conf': text})
    assert result['services'] == []
    assert result['dropped_entries'][0]['reason'] == 'attribute_needs_space_before_operator'


def test_parser_failure_disables_but_enabled_list_overrides_it():
    text = BACKDOOR.replace('wait        = no', 'wait        = maybe')
    result = _run({'/etc/xinetd.conf': text})
    svc = _svc(result, 'backdoor')
    assert svc['status'] == 'disabled'
    assert svc['disabled_reasons'] == ['attribute_parse_failed:wait']
    # An 'enabled' list re-enables the id; the failed attribute is still
    # unspecified, so service_attr_check then rejects it.
    with_list = 'defaults\n{\nenabled = backdoor\n}\n' + text
    svc = _svc(_run({'/etc/xinetd.conf': with_list}), 'backdoor')
    assert svc['disabled_reasons'] == ['missing_attribute:wait']


def test_disable_no_after_parse_failure_keeps_entry_and_unmodelled_is_unresolved():
    text = BACKDOOR.replace('    wait        = no\n',
                            '    wait        = maybe\n    disable     = no\n')
    result = _run({'/etc/xinetd.conf': text})
    svc = _svc(result, 'backdoor')
    # 'disable = no' re-enables after the wait parser failure, so the entry
    # is kept; the unparsed wait is then a missing required attribute.
    assert result['dropped_entries'] == []
    assert svc['disabled_reasons'] == ['missing_attribute:wait']
    text = BACKDOOR.replace('    wait        = no\n', '    wait        = no\n    nice        = x\n')
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'backdoor')
    assert svc['status'] == 'unresolved'
    assert svc['unmodelled_attributes'] == ['nice']


def test_defaults_enabled_and_disabled_lists():
    two = BACKDOOR + BACKDOOR.replace('backdoor', 'other').replace('31337', '31338')
    enabled = 'defaults\n{\nenabled = other\n}\n' + two
    result = _run({'/etc/xinetd.conf': enabled})
    assert result['loaded_services'] == ['other']
    assert _svc(result, 'backdoor')['disabled_reasons'] == ['not_in_defaults_enabled']
    disabled = 'defaults\n{\ndisabled = other\n}\n' + two
    result = _run({'/etc/xinetd.conf': disabled})
    assert result['loaded_services'] == ['backdoor']
    assert _svc(result, 'other')['disabled_reasons'] == ['in_defaults_disabled']


def test_missing_required_attributes_and_dgram_wait_rules():
    text = BACKDOOR.replace('    user        = root\n', '').replace('stream', 'dgram')
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'backdoor')
    assert svc['status'] == 'disabled'
    assert 'dgram_without_wait' in svc['disabled_reasons']
    assert 'missing_attribute:user' in svc['disabled_reasons']


def test_nameinargs_uses_server_args_as_full_argv():
    text = BACKDOOR.replace('    server_args = -i',
                            '    flags       = NAMEINARGS\n    server_args = tcpd /bin/sh -i')
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'backdoor')
    assert svc['argv'] == ['tcpd', '/bin/sh', '-i']


def test_listed_service_needs_services_lookup_and_numeric_uid_zero_is_root():
    text = """service telnet
{
    socket_type = stream
    wait        = no
    user        = 0
    server      = /usr/sbin/in.telnetd
}
"""
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'telnet')
    assert svc['runs_as_root'] is True
    assert 'services:telnet/<from socket_type>' in svc['required_lookups']
    assert svc['argv'] == ['in.telnetd']


def test_missing_brace_skips_to_next_close_brace():
    text = 'service a\n    socket_type = stream\n}\n' + BACKDOOR
    result = _run({'/etc/xinetd.conf': text})
    assert [s['name'] for s in result['services']] == ['backdoor']
    assert result['dropped_entries'][0]['reason'] == 'missing_open_brace'


def test_fail_closed_on_unobserved_or_unreadable_inputs():
    assert _run({})['complete'] is False
    assert _run({'/etc/xinetd.conf': None})['complete'] is False
    assert _run({'/etc/xinetd.conf': 'a\x00b'})['complete'] is False
    result = _run({'/etc/xinetd.conf': DEBIAN_MAIN})
    assert result['complete'] is False
    assert result['gaps'][0]['kind'] == 'directory_not_observed'
    assert 'debian_inetd_compat_and_etc_inetd_conf' in result['not_observed']


def test_include_cycle_is_a_blocking_gap():
    result = _run({'/etc/xinetd.conf': 'include /etc/xinetd.conf\n'})
    assert result['complete'] is False
    assert any(g['kind'] == 'include_depth_exceeded' for g in result['gaps'])


def test_internal_service_needs_services_lookup_and_has_no_argv():
    text = """service daytime
{
    type        = INTERNAL
    socket_type = stream
    protocol    = tcp
    wait        = no
}
"""
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'daytime')
    assert svc['status'] == 'loads_if_lookups_succeed'
    assert svc['internal'] is True and svc['builtin'] == 'daytime'
    assert svc['argv'] is None
    assert 'services:daytime/tcp' in svc['required_lookups']
    unlisted = text.replace('INTERNAL', 'INTERNAL UNLISTED')
    svc = _svc(_run({'/etc/xinetd.conf': unlisted}), 'daytime')
    assert 'unlisted_without_port' in svc['disabled_reasons']


def test_redirect_forwards_without_exec():
    text = BACKDOOR.replace('    server      = /bin/sh\n    server_args = -i\n',
                            '    redirect    = 10.0.0.5 22\n')
    svc = _svc(_run({'/etc/xinetd.conf': text}), 'backdoor')
    assert svc['status'] == 'loads_if_lookups_succeed'
    assert svc['argv'] is None
    assert svc['redirect'] == ['10.0.0.5', '22']
