"""Pure snmptrapd traphandle contract (#1431)."""
from app import snmptrapd_handlers as st

CONF = '/etc/snmp/snmptrapd.conf'


def run(text, user='root', extra=()):
    return st.evaluate(files=[{'path': CONF, 'exists': True, 'text': text}, *extra], service_user=user)


def test_handlers_without_execute_authorization_do_not_run():
    r = run('traphandle default /usr/local/bin/h\nauthCommunity log,net public\n')
    assert r['status'] == 'handlers_not_authorized' and r['complete'] and r['origin'] == 'not_assessed'
    assert r['authorization']['state'] == 'none'
    assert r['handlers'][0]['code_runs'] == 'not_authorized'


def test_execute_grant_runs_handlers_as_the_service_user_with_the_raw_command():
    r = run("  authCommunity log,execute public 10.0.0.0/8\ntraphandle -F '%B' default /bin/sh -c 'id -u >> /tmp/o'  \n")
    assert r['status'] == 'runs' and r['complete']
    h = r['handlers'][0]
    assert (h['match'], h['format'], h['command'], h['runs_as'], h['shell'], h['code_runs']) == (
        'default', '%B', "/bin/sh -c 'id -u >> /tmp/o'", 'root', '/bin/sh -c', 'on_matching_trap')
    assert r['authorization']['execute_grants'] == [CONF + ':1']
    assert r['authorization']['grants'][0]['arguments'] == 'public 10.0.0.0/8'


def test_disable_authorization_last_line_wins_and_directives_are_case_insensitive():
    on = run('DISABLEAUTHORIZATION Yes\nTrapHandle default echo hi\n')
    assert on['status'] == 'runs' and on['authorization']['state'] == 'disabled'
    off = run('disableAuthorization yes\ndisableAuthorization no\ntraphandle default echo hi\n')
    assert off['status'] == 'handlers_not_authorized'
    bad = run('disableAuthorization maybe\ntraphandle default echo hi\n')
    assert not bad['complete'] and bad['gaps'][0]['code'] == 'unparsed_disable_authorization'


def test_oid_match_flags_and_case_sensitive_default():
    r = run('disableAuthorization yes\n'
            'traphandle .1.3.6.1.4.1.8072.2.3.0.1 echo exact\n'
            'traphandle 1.3.6.1.4.1.8072.2.3.* echo tree\n'
            'traphandle 1.3.6.1.4.1.8072.2.3.0.1.* echo strict\n')
    spec = [(h['oid'], h['subtree'], h['strict_subtree'], h['command']) for h in r['handlers']]
    assert spec == [('.1.3.6.1.4.1.8072.2.3.0.1', False, False, 'echo exact'),
                    ('1.3.6.1.4.1.8072.2.3', True, True, 'echo tree'),
                    ('1.3.6.1.4.1.8072.2.3.0.1', True, True, 'echo strict')]
    assert r['complete']
    upper = run('disableAuthorization yes\ntraphandle DEFAULT echo x\n')
    assert upper['handlers'][0]['match'] == 'oid' and upper['gaps'][0]['code'] == 'symbolic_oid'
    assert not upper['complete']


def test_comments_missing_commands_and_no_backslash_continuation():
    r = run('disableAuthorization yes\n# traphandle default echo no\n'
            'traphandle default\ntraphandle default echo a \\\n b >> /tmp/o\n')
    assert [h['command'] for h in r['handlers']] == ['echo a \\']
    assert [g['code'] for g in r['gaps']] == ['traphandle_without_command']
    assert r['complete'] and r['status'] == 'runs'


def test_files_are_read_in_order_and_absent_files_are_reported():
    r = st.evaluate(files=[{'path': CONF, 'exists': False},
                           {'path': st.DEFAULT_FILES[1], 'exists': True,
                            'text': 'disableAuthorization yes\ntraphandle default echo p\n'}])
    assert [f['state'] for f in r['files']] == ['absent', 'read']
    assert r['handlers'][0]['source'] == st.DEFAULT_FILES[1] + ':2' and r['status'] == 'runs'
    none = st.evaluate(files=[{'path': CONF, 'exists': False}])
    assert none['status'] == 'absent' and none['complete'] and none['handlers'] == []


def test_fail_closed_inputs_are_incomplete():
    cases = {
        'file_not_checked': st.evaluate(files=[{'path': CONF, 'exists': None}]),
        'files_not_captured': st.evaluate(files=None),
        'nul_byte': run('traphandle default echo\x00x\n'),
        'invalid_utf8': run(b'traphandle default echo \xff\n'),
        'text_over_limit': run('#' * (st.MAX_TEXT_BYTES + 1)),
        'line_over_limit': run('traphandle default echo ' + 'x' * 1100 + '\n'),
        'include_not_resolved': run('includeFile /etc/snmp/more.conf\n'),
        'section_context': run('[snmp]\n'),
        'embedded_perl_handler': run('perl do "/etc/snmp/h.pl";\n'),
        'service_user_unknown': run('traphandle default echo\n', user=None),
        'text_not_captured': st.evaluate(files=[{'path': CONF, 'exists': True}]),
    }
    for code, r in cases.items():
        assert not r['complete'], code
        assert code in [g['code'] for g in r['gaps']], code


def test_authorized_handlers_stay_runs_even_when_other_input_is_incomplete():
    r = run('disableAuthorization yes\ntraphandle default echo hi\nincludeDir /etc/snmp/d\n')
    assert r['status'] == 'runs' and not r['complete']
    r2 = run('includeDir /etc/snmp/d\ntraphandle default echo hi\n')
    assert r2['status'] == 'unresolved'


def test_access_types_are_case_sensitive():
    r = run('authCommunity Execute,LOG public\ntraphandle default echo hi\n')
    assert r['authorization']['state'] == 'none' and r['status'] == 'handlers_not_authorized'


def test_a_later_authcommunity_line_for_the_same_community_does_not_grant_execute():
    r = run('authCommunity log public\nauthCommunity log,execute public\ntraphandle default echo hi\n')
    assert r['authorization']['grants'][1]['shadowed'] and r['status'] == 'handlers_not_authorized'
