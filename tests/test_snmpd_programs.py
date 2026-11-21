"""Contract tests for the net-snmp snmpd program contract (#1327).

Expected values are traced from net-snmp 5.9.4 (Ubuntu 24.04
``net-snmp_5.9.4+dfsg-1.1ubuntu3.3``): ``snmplib/read_config.c``,
``agent/mibgroup/agent/extend.c``, ``ucd-snmp/pass.c``,
``ucd-snmp/pass_persist.c``, ``utilities/execute.c``, ``util_funcs.c`` and
``agent/snmpd.c``.
"""
from __future__ import annotations

from app import snmpd_programs as sp

PASSWD = (
    'root:x:0:0:root:/root:/bin/bash\n'
    'Debian-snmp:x:110:116::/var/lib/snmp:/bin/false\n'
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
)
GROUP = 'root:x:0:\nDebian-snmp:x:116:\nnogroup:x:65534:\n'


def run(text, **kwargs):
    kwargs.setdefault('passwd_text', PASSWD)
    kwargs.setdefault('group_text', GROUP)
    return sp.evaluate([{'path': '/etc/snmp/snmpd.conf', 'text': text}], **kwargs)


def programs(result, **match):
    return [row for row in result['programs'] if all(row.get(k) == v for k, v in match.items())]


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def test_packaged_default_runs_extend_as_debian_snmp_and_is_never_complete():
    result = run('extend test1 /bin/echo hello world\n')
    row = programs(result, name='test1')[0]
    assert row['argv'] == ['/bin/echo', 'hello', 'world']
    assert (row['run_user'], row['run_uid'], row['run_group'], row['run_gid']) == ('Debian-snmp', 110, 'Debian-snmp', 116)
    assert row['exec_type'] == 'exec' and row['root_oid'] == sp.NS_EXTEND_OID
    assert result['complete'] is False and codes(result) == ['read_order_not_derived']
    assert result['origin'] == 'not_assessed' and result['authorizes_response'] is False


def test_shell_directives_run_through_bin_sh_and_case_variants_do_not():
    result = run(
        'extend-sh a echo hi | tr a-z A-Z\n'
        'sh b uptime; id\n'
        'sh2 c id\n'
        'extend -execType sh d id >/tmp/x\n'
        # strcasecmp finds the handler, strcmp then misses the shell flag.
        'EXTEND-SH e echo shout\n'
        'Sh f id\n'
    )
    for name in 'abcd':
        assert programs(result, name=name)[0]['argv'][:2] == ['/bin/sh', '-c'], name
    assert programs(result, name='a')[0]['argv'][2] == 'echo hi | tr a-z A-Z'
    assert programs(result, name='e')[0]['argv'] == ['echo', 'shout']
    assert programs(result, name='e')[0]['relative_program'] is True
    assert programs(result, name='f')[0]['exec_type'] == 'exec'


def test_quoting_backslashes_and_hash_words_follow_copy_nword():
    result = run(
        'extend q "/opt/my tool" "two words" x\\ y\n'
        'extend h /bin/x a #comment b\n'
        'extend m /bin/x a#b\n'
    )
    # The command word is dequoted at parse time, then the joined buffer is
    # tokenized again, so a quoted program path with a space splits at exec.
    assert programs(result, name='q')[0]['argv'] == ['/opt/my', 'tool', 'two words', 'x y']
    assert programs(result, name='h')[0]['argv'] == ['/bin/x', 'a']
    assert programs(result, name='m')[0]['argv'] == ['/bin/x', 'a#b']


def test_quoted_arguments_survive_as_raw_text_and_are_retokenized():
    result = run('extend r /bin/x "a b" \'c\'\n')
    assert programs(result, name='r')[0]['argv'] == ['/bin/x', 'a b', 'c']


def test_fix_suffix_writable_and_duplicate_names_keep_first_entry():
    result = run(
        'extend one /bin/a\n'
        'extendfix one /bin/fix\n'
        'execFix2 two /bin/fix2\n'
        'EXTENDFIX three /bin/f3\n'
        'extend one /bin/second\n'
        'extend .1.3.6.1.4.1.2021.60 one /bin/other-root\n'
    )
    assert programs(result, name='one', root_oid=sp.NS_EXTEND_OID)[0]['argv'] == ['/bin/a']
    assert programs(result, name='oneFix')[0]['writable'] is True
    assert programs(result, name='twoFix')[0]['writable'] is True
    assert programs(result, name='three')[0]['writable'] is False
    assert programs(result, name='one', root_oid='.1.3.6.1.4.1.2021.60')[0]['argv'] == ['/bin/other-root']
    assert {'line': 5, 'reason': 'duplicate_name'}.items() <= next(
        note for note in result['lines'] if note['line'] == 5).items()


def test_deprecated_exec_oid_form_and_symbolic_oid():
    result = run('exec .1.3.6.1.4.1.2021.50 legacy /bin/true\nextend .iso.org x /bin/x\n')
    assert result['programs'] == []
    assert result['lines'][0]['reason'] == 'deprecated_oid_form'
    assert 'oid_unresolved' in codes(result)


def test_cache_time_and_command_buffer_truncation():
    long_arg = 'a' * 600
    result = run(f'extend -cacheTime 30 t /bin/x {long_arg}\n')
    row = programs(result, name='t')[0]
    assert row['cache_time'] == 30 and row['command_truncated'] is True
    assert len(' '.join(row['argv'])) == sp.EXTEND_COMMAND_BUFFER - 1


def test_exec_tokenizer_keeps_remainder_after_98_words():
    words = ' '.join(f'w{i}' for i in range(120))
    argv = sp.tokenize_exec_command('/bin/x ' + words)
    assert len(argv) == 99 and argv[-1].startswith('w97 ')


def test_pass_takes_command_up_to_hash_or_semicolon_and_priority_strtol():
    result = run(
        'pass -p 0x10 .1.3.6.1.4.1.8072.2.255 /usr/bin/perl /usr/share/snmp/passtest.pl ; ignored\n'
        'pass .1.3.6.1.4.1.8072.2.1 /bin/y#tail\n'
        'pass 1.3.6.1.9 "/opt/q r"\n'
        'pass -x .1.3 /bin/z\n'
        'pass foo /bin/z\n'
    )
    first = programs(result, oid='.1.3.6.1.4.1.8072.2.255')[0]
    assert first['priority'] == 16 and first['argv_prefix'] == ['/usr/bin/perl', '/usr/share/snmp/passtest.pl']
    assert programs(result, oid='.1.3.6.1.4.1.8072.2.1')[0]['command'] == '/bin/y'
    assert programs(result, oid='.1.3.6.1.9')[0]['argv_prefix'] == ['/opt/q r']
    reasons = [note['reason'] for note in result['lines']]
    assert reasons[-2:] == ['unknown_option', 'oid_not_numeric']


def test_pass_option_without_value_crashes_snmpd_and_blocks():
    result = run('pass -p\n')
    assert result['programs'] == [] and 'snmpd_crash' in codes(result)


def test_pass_persist_splits_only_at_spaces():
    result = run('pass_persist .1.3.6.1.4.1.8072.2.254 /usr/bin/python3\t-u  /opt/pp.py # c\n')
    assert programs(result, module='pass_persist')[0]['argv'] == ['/usr/bin/python3\t-u', '/opt/pp.py']
    assert sp.parse_cmd('/bin/a  b #c d') == ['/bin/a', 'b']


def test_disabled_modules_suppress_only_their_rows():
    text = 'extend a /bin/a\npass .1.3.9 /bin/p\npass_persist .1.3.8 /bin/pp\n'
    argv = list(sp.DEFAULT_ARGV) + ['-I', '-extend,pass']
    result = run(text, argv=argv)
    assert [row['module'] for row in result['programs']] == ['pass_persist']
    only = run(text, argv=['/usr/sbin/snmpd', '-Ipass', '-f'])
    assert [row['module'] for row in only['programs']] == ['pass']
    assert only['run_identity']['uid'] == 0 and only['programs'][0]['run_user'] == 'root'


def test_agentuser_replaces_argv_user_and_unknown_name_keeps_previous():
    result = run('agentuser nobody\nagentgroup nogroup\nagentuser missing\nextend a /bin/a\n')
    row = programs(result, name='a')[0]
    assert (row['run_user'], row['run_uid'], row['run_group'], row['run_gid']) == ('nobody', 65534, 'nogroup', 65534)
    # "#123" starts a comment for read_config, so the handler never runs.
    hashed = run('agentuser #0\nextend a /bin/a\n')
    assert hashed['run_identity']['uid'] == 110


def test_unresolved_accounts_block_and_bad_argv_user_exits():
    result = run('extend a /bin/a\n', passwd_text=None)
    assert result['run_identity']['uid'] is None and 'accounts_not_observed' in codes(result)
    bad = run('extend a /bin/a\n', argv=['/usr/sbin/snmpd', '-u', 'ghost', '-f'])
    assert {'code': 'account_unresolved', 'name': 'ghost'}.items() <= bad['gaps'][-1].items()


def test_contexts_includes_code_loading_and_argv_configuration_are_gaps():
    result = run(
        '[snmp] extend no /bin/no\n'
        '[snmpd] extend yes /bin/yes\n'
        'includeFile other.conf\n'
        'include /etc/x\n'
        'dlmod foo /usr/lib/foo.so\n'
        'PERL do "/x.pl"\n'
        '[snmp]\n'
        'extend after /bin/after\n'
    )
    assert [row['name'] for row in result['programs']] == ['yes']
    assert {'include_not_modelled', 'code_loading_directive'} <= set(codes(result))
    assert run('[mystery]\nextend a /bin/a\n')['programs'] == []
    assert 'context_unresolved' in codes(run('[mystery]\nextend a /bin/a\n'))
    for extra in (['-c', '/x.conf'], ['-C'], ['-Y', 'extend a /bin/a'], ['--extend=a /bin/a']):
        assert 'argv_config_not_modelled' in codes(run('', argv=['/usr/sbin/snmpd', *extra]))
    assert 'argv_invalid' in codes(run('', argv=['/usr/sbin/snmpd', '-Z']))


def test_unobserved_invalid_and_nul_files_block():
    result = sp.evaluate([
        {'path': '/etc/snmp/snmpd.conf', 'text': None},
        {'path': '/etc/snmp/snmpd.local.conf', 'text': b'\xff'},
        {'path': '/var/lib/snmp/snmpd.conf', 'text': 'extend a /bin/a\0'},
    ], passwd_text=PASSWD, group_text=GROUP)
    assert result['programs'] == []
    assert codes(result)[1:] == ['file_not_observed', 'file_invalid', 'file_invalid']


def test_utf8_names_and_arguments_round_trip():
    result = run('extend café /opt/naïve "é ü"\n')
    row = programs(result, name='café')[0]
    assert row['argv'] == ['/opt/naïve', 'é ü']


def test_non_ascii_digits_are_not_c_digits():
    # Byte 0xB2 of a UTF-8 sequence is "²" in latin-1, which Python calls a digit.
    result = run('pass .1.3.\u00b2 /bin/p\npass \u00b2 /bin/q\n')
    assert [row['oid'] for row in result['programs']] == ['.1.3.']
    assert result['lines'][-1]['reason'] == 'oid_not_numeric'
