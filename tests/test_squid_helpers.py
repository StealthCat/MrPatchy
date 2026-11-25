"""Tests for the pure Squid helper-program contract (#1519)."""
from __future__ import annotations

from app import squid_helpers as sh

CONF = '/etc/squid/squid.conf'


def run(text, includes=None, process=None):
    payload = {'config': {'path': CONF, 'text': text}, 'includes': includes or {}}
    if process is not None:
        payload['process'] = process
    return sh.evaluate(payload)


def helpers(result):
    return [(h['kind'], h['name'], h['executable'], h['argv']) for h in result['helpers']]


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_url_rewrite_store_id_and_run_as_user():
    result = run('cache_effective_user proxy\n'
                 'url_rewrite_program /usr/lib/squid/rewrite --flag "a b"\n'
                 'store_id_program /usr/bin/storeid\n'
                 'cache_effective_group proxy\n')
    assert helpers(result) == [('url_rewrite', None, '/usr/lib/squid/rewrite', ['(rewrite)', '--flag', 'a b']),
                               ('store_id', None, '/usr/bin/storeid', ['(storeid)'])]
    assert result['run_as']['user'] == 'proxy'
    assert result['run_as']['user_source'] == 'cache_effective_user'
    assert result['run_as']['group'] == 'proxy'
    assert result['complete'] is True


def test_default_run_as_is_compiled_default():
    result = run('http_port 3128\n')
    assert result['helpers'] == []
    assert result['run_as']['user'] is None and result['run_as']['user_source'] == 'compiled_default'
    assert result['run_as']['group_source'] == 'user_primary_group'
    assert result['complete'] is True


def test_repeated_wordlist_directives_append_including_aliases():
    result = run('url_rewrite_program /a one\nredirect_program two\n'
                 'store_id_program /s\nstoreurl_rewrite_program x\n')
    assert helpers(result) == [('url_rewrite', None, '/a', ['(a)', 'one', 'two']),
                               ('store_id', None, '/s', ['(s)', 'x'])]
    assert [entry['directive'] for entry in result['helpers'][0]['lines']] == ['url_rewrite_program',
                                                                                'redirect_program']


def test_auth_program_last_wins_per_scheme_and_other_params_ignored():
    result = run('auth_param basic program /old\n'
                 'auth_param basic children 5\n'
                 'auth_param basic realm Proxy "x\n'
                 'auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -s GSS_C_NO_NAME\n'
                 'auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd\n')
    assert helpers(result) == [
        ('auth', 'basic', '/usr/lib/squid/basic_ncsa_auth', ['(basic_ncsa_auth)', '/etc/squid/passwd']),
        ('auth', 'negotiate', '/usr/lib/squid/negotiate_kerberos_auth',
         ['(negotiate_kerberos_auth)', '-s', 'GSS_C_NO_NAME'])]
    assert result['complete'] is True


def test_unknown_auth_scheme_and_empty_program_block():
    assert 'unknown_auth_scheme' in codes(run('auth_param Basic program /x\n'))
    result = run('auth_param basic program\n')
    assert 'empty_program' in codes(result) and result['complete'] is False


def test_external_acl_options_formats_and_helper():
    result = run('external_acl_type grp ttl=60 children-max=5 ipv4 %LOGIN %>{Host} /usr/lib/squid/ext_unix_group '
                 '-p "-g x"\n'
                 'external_acl_type other %SRC helper\n')
    assert helpers(result) == [
        ('external_acl', 'grp', '/usr/lib/squid/ext_unix_group', ['(ext_unix_group)', '-p', '-g x']),
        ('external_acl', 'other', 'helper', ['(helper)'])]
    first, second = result['helpers']
    assert first['options'] == ['ttl=60', 'children-max=5', 'ipv4']
    assert first['format'] == ['%LOGIN', '%>{Host}']
    assert first['path_lookup'] is False and second['path_lookup'] is True
    assert result['complete'] is True


def test_external_acl_without_format_or_helper_blocks():
    assert 'external_acl_malformed' in codes(run('external_acl_type a /bin/helper\n'))
    assert 'external_acl_malformed' in codes(run('external_acl_type a ttl=5 %SRC\n'))


def test_comments_continuation_and_whitespace():
    result = run('  # comment\n\n'
                 'url_rewrite_program /bin/r \\\n'
                 '# a comment line inside a continuation is skipped\n'
                 '     arg1 \\\n'
                 '\targ2   \n'
                 'store_id_program /bin/s # trailing comment\n')
    assert helpers(result) == [('url_rewrite', None, '/bin/r', ['(r)', 'arg1', 'arg2']),
                               ('store_id', None, '/bin/s', ['(s)'])]
    assert result['helpers'][0]['lines'][0]['line'] == 3


def test_backslash_followed_by_space_is_not_a_continuation():
    result = run('url_rewrite_program /bin/r \\ \nstore_id_program /bin/s\n')
    assert helpers(result) == [('url_rewrite', None, '/bin/r', ['(r)', '\\']),
                               ('store_id', None, '/bin/s', ['(s)'])]


def test_carriage_return_truncates_the_physical_line():
    result = run('url_rewrite_program /bin/r\r /bin/hidden\n')
    assert helpers(result) == [('url_rewrite', None, '/bin/r', ['(r)'])]


def test_directive_names_are_case_sensitive():
    assert run('URL_REWRITE_PROGRAM /bin/r\n')['helpers'] == []


def test_wordlist_quotes_escapes_and_hash():
    result = run("url_rewrite_program /bin/r 'one two' \"t\\tab\" x#y #rest ignored\n")
    assert result['helpers'][0]['argv'] == ['(r)', 'one two', 't\tab', 'x#y']


def test_quoted_token_errors_block():
    assert 'quoted_token_malformed' in codes(run('url_rewrite_program /bin/r "open\n'))
    assert 'quoted_token_malformed' in codes(run('url_rewrite_program /bin/r "a"b\n'))
    assert 'quoted_token_malformed' in codes(run('url_rewrite_program /bin/r "\\q"\n'))


def test_parameters_function_and_unknown_function_block():
    result = run('url_rewrite_program /bin/r parameters("/etc/squid/args")\n')
    assert 'parameters_function' in codes(result) and result['complete'] is False
    assert 'parameters_function' in codes(run('url_rewrite_program /bin/r param("/x")\n'))
    assert 'unknown_cfg_function' in codes(run('url_rewrite_program /bin/r func("/x")\n'))


def test_quoted_values_setting_quotes_values_and_enables_strict_mode():
    result = run('configuration_includes_quoted_values on\ncache_effective_user "squid"\n')
    assert result['run_as']['user'] == 'squid'
    assert 'strict_mode_token' in codes(run('configuration_includes_quoted_values on\n'
                                            'url_rewrite_program /bin/r a*b\n'))
    off = run('cache_effective_user "squid"\n')
    assert off['run_as']['user'] == '"squid"'


def test_if_else_endif_and_innermost_state_quirk():
    result = run('if false\nurl_rewrite_program /bin/no\nelse\nurl_rewrite_program /bin/yes\nendif\n'
                 'if 0x1 = 1\nstore_id_program /bin/s\nendif\n')
    assert helpers(result) == [('url_rewrite', None, '/bin/yes', ['(yes)']),
                               ('store_id', None, '/bin/s', ['(s)'])]
    nested = run('if false\nif true\nurl_rewrite_program /bin/leak\nendif\nendif\n')
    assert helpers(nested) == [('url_rewrite', None, '/bin/leak', ['(leak)'])]


def test_if_errors_block():
    assert 'if_expression_invalid' in codes(run('if yes\nendif\n'))
    assert 'unterminated_if' in codes(run('if true\n'))
    assert 'endif_without_if' in codes(run('endif\n'))
    assert 'else_without_if' in codes(run('else\n'))


def test_process_macros_need_context():
    text = 'if ${process_number} = 1\nurl_rewrite_program /bin/r ${service_name}\nendif\n'
    blocked = run(text)
    assert 'runtime_macro' in codes(blocked) and blocked['complete'] is False
    first = run(text, process={'service_name': 'squid', 'process_name': 'squid-1', 'process_number': 1})
    assert helpers(first) == [('url_rewrite', None, '/bin/r', ['(r)', 'squid'])]
    assert first['complete'] is True
    second = run(text, process={'service_name': 'squid', 'process_name': 'squid-2', 'process_number': 2})
    assert second['helpers'] == []


def test_includes_in_glob_order_and_depth():
    includes = {'/etc/squid/conf.d/*.conf': [
        {'path': '/etc/squid/conf.d/a.conf', 'text': 'url_rewrite_program /bin/a\n'},
        {'path': '/etc/squid/conf.d/b.conf', 'text': 'redirect_program more\ninclude /etc/squid/x\n'}],
        '/etc/squid/x': [{'path': '/etc/squid/x', 'text': 'cache_effective_user nobody\n'}]}
    result = run('include /etc/squid/conf.d/*.conf\n', includes)
    assert helpers(result) == [('url_rewrite', None, '/bin/a', ['(a)', 'more'])]
    assert result['helpers'][0]['lines'][1]['file'] == '/etc/squid/conf.d/b.conf'
    assert result['run_as']['user'] == 'nobody'
    assert result['complete'] is True


def test_include_gaps():
    assert 'include_not_observed' in codes(run('include /etc/squid/missing\n'))
    assert 'include_no_match' in codes(run('include /etc/squid/none/*\n', {'/etc/squid/none/*': []}))
    assert 'include_quoting' in codes(run('include "/etc/squid/a b"\n'))
    loop = {'/l': [{'path': '/l', 'text': 'include /l\n'}]}
    assert 'include_too_deep' in codes(run('include /l\n', loop))


def test_argv_truncates_at_helper_max_args():
    words = ' '.join(f'a{i}' for i in range(80))
    helper = run(f'url_rewrite_program /bin/r {words}\n')['helpers'][0]
    assert len(helper['argv']) == 64 and helper['argv'][-1] == 'a62'
    assert helper['arguments_dropped'] == 17


def test_unmodelled_helper_directives_and_input_limits_block():
    assert 'unmodelled_helper_directive' in codes(run('sslcrtd_program /usr/lib/squid/security_file_certgen\n'))
    assert 'line_too_long' in codes(run('url_rewrite_program /bin/r ' + 'a' * 9000 + '\n'))
    assert 'nul_byte' in codes(run('url_rewrite_program /bin/r\x00\n'))
    assert 'input_malformed' in codes(sh.evaluate({'config': {'path': CONF}, 'includes': {}}))
    assert 'input_malformed' in codes(sh.evaluate(None))


def test_result_is_not_a_verdict():
    result = run('url_rewrite_program /bin/r\n')
    assert result['note'] == sh.NOT_A_VERDICT
    assert result['reference'] == {'squid': '6.10'}
    assert result['unobserved']
