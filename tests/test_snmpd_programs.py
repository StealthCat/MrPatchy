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


# --- Increment 2: read order derived from a filesystem snapshot (read_config.c) ---

PACKAGED_DIRS = {
    '/etc/snmp': [],
    '/usr/share/snmp': ['mibs'],
    '/usr/lib/x86_64-linux-gnu/snmp': [],
    '/var/lib/snmp': [],
}


def snap(files, directories=None, absent=()):
    dirs = dict(PACKAGED_DIRS)
    dirs.update(directories or {})
    for path in files:
        parent, _, name = path.rpartition('/')
        if parent in dirs and dirs[parent] is not None and name not in dirs[parent]:
            dirs[parent] = [*dirs[parent], name]
    return {'files': files, 'directories': dirs, 'absent': list(absent)}


def run_snapshot(files, directories=None, absent=(), **kwargs):
    kwargs.setdefault('passwd_text', PASSWD)
    kwargs.setdefault('group_text', GROUP)
    kwargs.setdefault('environ', {})
    return sp.evaluate_snapshot(snap(files, directories, absent), **kwargs)


def order(result):
    return [entry['path'] for entry in result['read_order']]


def test_packaged_search_path_without_home_reads_etc_then_persistent_and_completes():
    result = run_snapshot({
        '/etc/snmp/snmpd.conf': 'extend test1 /bin/echo hi\n',
        '/var/lib/snmp/snmpd.conf': 'setserialno 1\n',
    })
    assert order(result) == ['/etc/snmp/snmpd.conf', '/var/lib/snmp/snmpd.conf']
    assert result['search_path'] == '/etc/snmp:/usr/share/snmp:/usr/lib/x86_64-linux-gnu/snmp'
    assert result['complete'] is True and result['gaps'] == []
    assert programs(result, name='test1')[0]['run_user'] == 'Debian-snmp'
    assert result['authorizes_response'] is False and result['origin'] == 'not_assessed'


def test_local_conf_home_and_persistent_backups_follow_read_config_files_in_path():
    files = {
        '/etc/snmp/snmpd.conf': 'extend dup /bin/first\n',
        '/etc/snmp/snmpd.local.conf': 'extend dup /bin/second\nextend local /bin/local\n',
        '/root/.snmp/snmpd.conf': 'extend home /bin/home\n',
        '/var/lib/snmp/snmpd.0.conf': 'extend backup0 /bin/b0\n',
        '/var/lib/snmp/snmpd.1.conf': 'extend backup1 /bin/b1\n',
        # snmpd.2.conf is missing, so snmpd.3.conf is never read.
        '/var/lib/snmp/snmpd.3.conf': 'extend backup3 /bin/b3\n',
        '/var/lib/snmp/snmpd.conf': '',
    }
    result = run_snapshot(files, {'/root/.snmp': []}, environ={'HOME': '/root'})
    assert order(result) == [
        '/etc/snmp/snmpd.conf', '/etc/snmp/snmpd.local.conf', '/root/.snmp/snmpd.conf',
        '/var/lib/snmp/snmpd.0.conf', '/var/lib/snmp/snmpd.1.conf', '/var/lib/snmp/snmpd.conf',
    ]
    assert programs(result, name='dup')[0]['argv'] == ['/bin/first']
    assert {row['name'] for row in result['programs']} == {'dup', 'local', 'home', 'backup0', 'backup1'}
    assert result['complete'] is True


def test_snmpconfpath_replaces_the_search_and_skips_empty_elements():
    files = {
        '/opt/a/snmpd.conf': 'extend a /bin/a\n',
        '/etc/snmp/snmpd.conf': 'extend etc /bin/etc\n',
        '/opt/b/snmpd.conf': 'extend b /bin/b\n',
    }
    dirs = {'/opt/a': [], '/opt/b': []}
    # read_config_files_in_path stops only when the remaining string is empty; a
    # middle empty element is stat("") and is skipped, so /opt/b is still read.
    result = run_snapshot(files, dirs, environ={'SNMPCONFPATH': '/opt/a::/opt/b'})
    assert order(result) == ['/opt/a/snmpd.conf', '/opt/b/snmpd.conf']
    assert [row['name'] for row in result['programs']] == ['a', 'b']
    assert result['complete'] is True


def test_snmpconfpath_leading_or_middle_empty_element_does_not_hide_programs():
    # Regression: SNMPCONFPATH=":<dir>" or "/nonexistent::<dir>" made the contract
    # read nothing and still report complete, while real snmpd reads <dir>.
    files = {'/tmp/x/snmpd.conf': 'extend evilx /tmp/evil.sh\n'}
    for confpath in (':/tmp/x', '/nonexistent::/tmp/x'):
        result = run_snapshot(files, {'/tmp/x': []}, absent=('/nonexistent',),
                              environ={'SNMPCONFPATH': confpath})
        assert order(result) == ['/tmp/x/snmpd.conf'], confpath
        assert [row['argv'] for row in programs(result, name='evilx')] == [['/tmp/evil.sh']], confpath
        assert result['complete'] is True, confpath
    # A trailing empty element still ends the list: nothing follows it.
    result = run_snapshot(files, {'/tmp/x': []}, environ={'SNMPCONFPATH': '/tmp/x:'})
    assert order(result) == ['/tmp/x/snmpd.conf']


def test_snmpconfpath_persistent_directory_prefix_reads_backups():
    # The persistent directory is read only when it is in SNMPCONFPATH; prefix match gets backups.
    result = run_snapshot({'/var/lib/snmp/snmpd.0.conf': 'extend p0 /bin/p0\n', '/var/lib/snmp/snmpd.conf': ''},
                          environ={'SNMPCONFPATH': '/var/lib/snmp'})
    assert order(result) == ['/var/lib/snmp/snmpd.0.conf', '/var/lib/snmp/snmpd.conf']


def test_include_file_dir_and_search_resolve_with_the_includers_context():
    files = {
        '/etc/snmp/snmpd.conf': (
            'includeFile extra.conf\n'
            'includeDir /etc/snmp/snmpd.conf.d\n'
            'includeSearch site.conf\n'
            'includeFile /etc/snmp/missing.conf\n'
            'extend after /bin/after\n'
        ),
        # The context switch inside the included file does not leak back.
        '/etc/snmp/extra.conf': 'extend extra /bin/extra\n[snmp]\nextend ignored /bin/no\n',
        '/etc/snmp/snmpd.conf.d/one.conf': 'extend one /bin/one\n',
        '/etc/snmp/site.conf': 'extend site /bin/site\n',
    }
    dirs = {'/etc/snmp/snmpd.conf.d': ['.hidden.conf', 'notes.txt', 'one.conf', '.conf']}
    result = run_snapshot(files, dirs)
    assert order(result)[:4] == [
        '/etc/snmp/snmpd.conf', '/etc/snmp/extra.conf', '/etc/snmp/snmpd.conf.d/one.conf', '/etc/snmp/site.conf',
    ]
    assert [row['name'] for row in result['programs']] == ['extra', 'one', 'site', 'after']
    assert any(note['reason'] == 'not_found' for note in result['lines'])
    assert result['complete'] is True, result['gaps']


def test_include_target_keeps_trailing_blanks_and_relative_include_dir_blocks():
    result = run_snapshot({'/etc/snmp/snmpd.conf': 'includeFile /etc/snmp/x.conf  \nincludeDir conf.d\n',
                           '/etc/snmp/x.conf': 'extend x /bin/x\n'})
    # "/etc/snmp/x.conf  " does not exist, so x.conf is not read.
    assert programs(result, name='x') == []
    assert 'include_dir_relative' in codes(result) and result['complete'] is False


def test_include_dir_with_several_entries_blocks_on_readdir_order():
    files = {
        '/etc/snmp/snmpd.conf': 'includeDir /etc/snmp/d\n',
        '/etc/snmp/d/a.conf': 'extend same /bin/a\n',
        '/etc/snmp/d/b.conf': 'extend same /bin/b\n',
    }
    result = run_snapshot(files, {'/etc/snmp/d': ['b.conf', 'a.conf']})
    assert 'include_dir_order_unknown' in codes(result) and result['complete'] is False
    # Rows still follow the captured listing order.
    assert programs(result, name='same')[0]['argv'] == ['/bin/b']


def test_include_nesting_deeper_than_sixteen_is_refused():
    result = run_snapshot({'/etc/snmp/snmpd.conf': 'includeFile snmpd.conf\nextend loop /bin/loop\n'})
    depths = [entry['depth'] for entry in result['read_order'] if entry['path'] == '/etc/snmp/snmpd.conf']
    assert max(depths) == sp.MAX_INCLUDE_DEPTH and len(depths) == sp.MAX_INCLUDE_DEPTH + 1
    assert any(note['reason'] == 'include_depth_exceeded' for note in result['lines'])
    assert len(programs(result, name='loop')) == 1


def test_snmp_type_files_persistent_dir_and_cross_type_handlers_block():
    result = run_snapshot({'/etc/snmp/snmpd.conf': '', '/etc/snmp/snmp.conf': 'mibs +ALL\n'})
    assert order(result) == ['/etc/snmp/snmpd.conf', '/etc/snmp/snmp.conf'] and result['complete'] is True
    result = run_snapshot({'/etc/snmp/snmpd.conf': '', '/etc/snmp/snmp.conf': 'persistentDir /tmp/p\n'})
    assert 'persistent_dir_directive' in codes(result)
    result = run_snapshot({'/etc/snmp/snmpd.conf': '[snmp] persistentDir /tmp/p\n'})
    assert 'persistent_dir_directive' in codes(result)
    result = run_snapshot({'/etc/snmp/snmpd.conf': '', '/etc/snmp/snmp.conf': '[snmpd] extend s /bin/s\n'})
    assert programs(result, name='s') and 'type_order_not_derived' in codes(result)
    assert result['complete'] is False


def test_undescribed_paths_environment_and_argv_configuration_block():
    snapshot = {'files': {'/etc/snmp/snmpd.conf': ''}, 'directories': {'/etc/snmp': ['snmpd.conf']}}
    result = sp.evaluate_snapshot(snapshot, passwd_text=PASSWD, group_text=GROUP)
    assert 'environment_not_observed' in codes(result)
    assert {'/usr/share/snmp', '/var/lib/snmp'} <= {gap.get('path') for gap in result['gaps']}
    assert result['complete'] is False
    result = run_snapshot({'/etc/snmp/snmpd.conf': ''}, argv=[*sp.DEFAULT_ARGV, '-Y', 'extend a /bin/a'])
    assert 'argv_config_not_modelled' in codes(result)
    result = run_snapshot({'/etc/snmp/snmpd.conf': None})
    assert 'file_not_observed' in codes(result)
    long_dir = '/' + 'd' * 290
    result = run_snapshot({}, {long_dir: []}, environ={'SNMPCONFPATH': long_dir})
    assert 'path_truncated' in codes(result)


def test_argv_c_files_read_after_or_with_a_dash_before_the_search_path():
    files = {
        '/etc/snmp/snmpd.conf': 'extend dup /bin/etc\n',
        '/opt/one.conf': 'extend dup /bin/one\nextend one /bin/one\n',
        '/opt/two.conf': '[snmp]\nextend no /bin/no\n',
    }
    dirs = {'/opt': ['one.conf', 'two.conf']}
    after = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-c', '/opt/one.conf,,/opt/missing.conf,/opt/two.conf'])
    assert order(after) == ['/etc/snmp/snmpd.conf', '/opt/one.conf', '/opt/two.conf']
    assert programs(after, name='dup')[0]['argv'] == ['/bin/etc'] and programs(after, name='no') == []
    assert after['complete'] is True, after['gaps']
    # The last -c wins, and a leading '-' reads its files first.
    before = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-c', '/opt/two.conf', '-c', '-/opt/one.conf'])
    assert order(before) == ['/opt/one.conf', '/etc/snmp/snmpd.conf']
    assert programs(before, name='dup')[0]['argv'] == ['/bin/one']
    relative = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-c', 'one.conf'])
    assert 'optional_config_relative' in codes(relative) and relative['complete'] is False


def test_dash_capital_c_skips_both_types_persistent_files_and_include_search():
    """``-C`` sets DONT_READ_CONFIGS, so ``read_config_files_of_type`` returns at once (snmpd.c, read_config.c)."""
    files = {
        '/etc/snmp/snmpd.conf': 'extend etc /bin/etc\n',
        '/etc/snmp/snmpd.local.conf': 'extend local /bin/local\n',
        '/etc/snmp/snmp.conf': '[snmpd] extend cross /bin/cross\n',
        '/var/lib/snmp/snmpd.conf': 'extend persistent /bin/persistent\n',
        '/var/lib/snmp/snmpd.0.conf': 'extend backup /bin/backup\n',
        '/opt/only.conf': (
            'extend only /bin/only\n'
            'includeSearch site.conf\n'
            'includeFile /opt/inc.conf\n'
            'includeDir /opt/d\n'
        ),
        '/opt/inc.conf': 'extend inc /bin/inc\n',
        '/opt/d/one.conf': 'extend dir /bin/dir\n',
        '/etc/snmp/site.conf': 'extend site /bin/site\n',
    }
    dirs = {'/opt': ['only.conf', 'inc.conf', 'd'], '/opt/d': ['one.conf']}
    base = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-c', '/opt/only.conf'])
    assert {'etc', 'local', 'persistent', 'backup', 'site', 'only'} <= {row['name'] for row in base['programs']}
    assert base['default_configs_read'] is True

    result = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-C', '-c', '/opt/only.conf'])
    assert order(result) == ['/opt/only.conf', '/opt/inc.conf', '/opt/d/one.conf']
    assert [row['name'] for row in result['programs']] == ['only', 'inc', 'dir']
    assert all(row['run_user'] == 'Debian-snmp' for row in result['programs'])
    assert result['default_configs_read'] is False
    assert {'path': '/opt/only.conf', 'line': 2, 'directive': 'includeSearch', 'status': 'rejected',
            'reason': 'config_load_disabled'} in result['lines']
    # Fully derived: no argv_config_not_modelled or cross-type gap remains.
    assert result['complete'] is True, result['gaps']
    assert result['contract_version'] == 2 and result['authorizes_response'] is False

    # Option order and a leading '-' on -c do not matter: -C is a boolean.
    before = run_snapshot(files, dirs, argv=[*sp.DEFAULT_ARGV, '-c', '-/opt/only.conf', '-C'])
    assert [row['name'] for row in before['programs']] == ['only', 'inc', 'dir']
    # Bundled with other flags, as glibc getopt allows.
    bundled = run_snapshot(files, dirs, argv=['/usr/sbin/snmpd', '-LOw', '-u', 'Debian-snmp', '-g', 'Debian-snmp',
                                              '-I', '-smux,mteTrigger,mteTriggerConf', '-fC', '-p', '/run/x.pid'])
    assert bundled['programs'] == [] and bundled['read_order'] == [] and bundled['complete'] is True


def test_dash_capital_c_without_c_reads_nothing_and_does_not_need_the_search_path():
    # Undescribed search-path directories would be blocking gaps; -C never visits them.
    snapshot = {'files': {}, 'directories': {}}
    result = sp.evaluate_snapshot(snapshot, argv=[*sp.DEFAULT_ARGV, '-C'], environ={},
                                  passwd_text=PASSWD, group_text=GROUP)
    assert result['read_order'] == [] and result['programs'] == []
    assert result['complete'] is True, result['gaps']
    # An unobserved environment still blocks, and evaluate() still treats -C as unmodelled.
    unobserved = sp.evaluate_snapshot(snapshot, argv=[*sp.DEFAULT_ARGV, '-C'], passwd_text=PASSWD, group_text=GROUP)
    assert 'environment_not_observed' in codes(unobserved) and unobserved['complete'] is False
    trusted = run('extend a /bin/a\n', argv=[*sp.DEFAULT_ARGV, '-C'])
    assert {'code': 'argv_config_not_modelled', 'blocking': True, 'option': 'C'} in trusted['gaps']
