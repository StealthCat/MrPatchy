"""keepalived script-line contract, first increment (#1307), against traced keepalived 2.2.8 semantics."""
from app import keepalived_scripts as ks


def texts(conf, **kw):
    r = ks.logical_lines(conf, **kw)
    return [line['text'].decode() for line in r['lines']], r


def test_comments_quotes_and_escaped_comment_characters():
    assert ks.decomment(b'  notify /bin/x # c') == (b'notify /bin/x', False)
    assert ks.decomment(b'notify "/bin/x # kept" ! c') == (b'notify "/bin/x # kept"', False)
    assert ks.decomment(b'notify /bin/x\\#y') == (b'notify /bin/x#y', False)
    assert ks.decomment(b'notify "/bin/x\\#y"') == (b'notify "/bin/x\\#y"', False)
    assert ks.decomment(b'notify "/bin/x')[1] is True


def test_braces_are_split_onto_their_own_lines():
    lines, r = texts('vrrp_instance VI_1 {\n  notify_master /bin/m } \n{ state BACKUP }\n')
    assert lines == ['vrrp_instance VI_1', '{', 'notify_master /bin/m', '}', '{', 'state BACKUP', '}']
    assert r['complete']
    lines, _ = texts('notify "/bin/sh -c \'echo }\'"\n')
    assert lines == ['notify "/bin/sh -c \'echo }\'"']


def test_unmodelled_preprocessing_fails_closed():
    for conf, code in (('include /etc/keepalived/conf.d/*.conf\n', 'include'),
                       ('$IF=eth0\n', 'definition'),
                       ('notify /bin/x $_RANDOM\n', 'parameter_expansion'),
                       ('notify /bin/x ${_INSTANCE}\n', 'parameter_expansion'),
                       ('~SEQ(i,1,3) notify /bin/x\n', 'sequence'),
                       ('@node1 notify /bin/x\n', 'conditional_unresolved'),
                       ('notify /bin/x \\\n', 'continuation'),
                       ('notify /bin/' + 'x' * 1100 + '\n', 'line_over_buffer')):
        r = ks.logical_lines(conf)
        assert not r['complete'] and r['gaps'][0]['code'] == code, conf
    for raw, code in ((b'a\0b', 'binary'), (b'\xff', 'invalid_utf8'), (b'x' * (ks.MAX_TEXT + 1), 'over_limit')):
        assert ks.logical_lines(raw)['gaps'][0]['code'] == code


def test_dollar_that_no_standard_definition_matches_is_left_alone():
    lines, r = texts('notify "/bin/sh -c \'echo $1 $HOME\'"\n')
    assert r['complete'] and lines == ['notify "/bin/sh -c \'echo $1 $HOME\'"']


def test_conditional_lines_follow_the_observed_config_id():
    conf = '@node1 notify /bin/a\n@^node1 notify /bin/b\n@node2 notify /bin/c\n@node1\n'
    lines, r = texts(conf, config_id='node1')
    assert lines == ['notify /bin/a'] and r['complete']
    lines, _ = texts(conf, config_id='node2')
    assert lines == ['notify /bin/b', 'notify /bin/c']


def test_line_at_buffer_limit_is_whole():
    line = 'notify /bin/' + 'x' * (ks.MAXBUF - 1 - len('notify /bin/'))
    assert len(line) == ks.MAXBUF - 1
    assert ks.logical_lines(line + '\n')['complete']
    assert not ks.logical_lines(line + 'x\n')['complete']


def test_quoted_escaped_split_matches_keepalived_escapes():
    q = ks.split_quoted_escaped
    assert q(b"a 'b c' \"d e\" f\\ g") == [b'a', b'b c', b'd e', b'f g']
    assert q(b'\\x41\\101\\cA\\t\\q') == [b'AA\x01\tq']
    assert q(b'\\x4142') == [b'B']  # hex digits accumulate into one byte
    assert q(b'a\\0b c') == [b'a', b'c']  # STRNDUP stops at the escaped NUL
    assert q(b"'it\\'s'") == [b"it's"]
    assert q(b'"unterminated') is None and q(b'end\\') is None and q(b'   ') is None


def test_script_line_reparses_the_script_word_and_reads_user_group():
    r = ks.script_line(b'notify_master "/usr/local/bin/m \\"a b\\" c" svc grp extra')
    assert r == {'status': 'ok', 'reason': None, 'argv': ['/usr/local/bin/m', 'a b', 'c'],
                 'user': 'svc', 'group': 'grp'}
    r = ks.script_line(b"startup_script '/bin/echo hi'")
    assert r['argv'] == ['/bin/echo', 'hi'] and r['user'] is None and r['group'] is None
    assert ks.script_line(b'notify')['status'] == 'ignored'
    assert ks.script_line(b'notify "/bin/x \'oops"')['reason'] == 'no_script'


def test_double_quoted_keyword_tokenizing():
    assert ks.split_words(b'vrrp_script "chk web" {') == [b'vrrp_script', b'chk web', b'{']
    assert ks.split_words(b'a "b') == [b'a']
    assert ks.split_words(b'a"b"') == [b'a', b'b']


# --- Increment 2: the VRRP process block walk, traced against keepalived 2.2.8 process_stream ---------

CONF = '''
global_defs {
    router_id lb1
    notification_email {
        ops@example.test
    }
}
vrrp_script chk_web {
    script "/usr/local/bin/check web"
    interval 2
    user nobody nogroup
}
vrrp_script chk_db {
    script /usr/local/bin/check-db
}
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    authentication {
        auth_type PASS
        auth_pass secret
    }
    virtual_ipaddress {
        192.0.2.10/24
    }
    track_script {
        chk_web
        notify_master /not/a/keyword
    }
    notify_master "/etc/keepalived/master.sh 'two words'" svc
    notify_master /ignored/second
    notify /etc/keepalived/notify.sh
}
vrrp_sync_group G1 {
    group {
        VI_1
    }
    notify_fault /etc/keepalived/fault.sh
}
'''


def progs(conf, **kw):
    r = ks.vrrp_programs(conf, **kw)
    return [(p['block'], p['name'], p['keyword'], p['argv'], p['user'], p['user_source']) for p in r['programs']], r


def test_programs_users_and_value_blocks():
    found, r = progs(CONF, keepalived_script_exists=True)
    assert r['complete'], r['gaps']
    assert found == [
        ('vrrp_script', 'chk_web', 'script', ['/usr/local/bin/check', 'web'], 'nobody', 'configured'),
        ('vrrp_script', 'chk_db', 'script', ['/usr/local/bin/check-db'], 'keepalived_script',
         'default:keepalived_script'),
        ('vrrp_instance', 'VI_1', 'notify_master', ['/etc/keepalived/master.sh', 'two words'], 'svc', 'configured'),
        ('vrrp_instance', 'VI_1', 'notify', ['/etc/keepalived/notify.sh'], 'keepalived_script',
         'default:keepalived_script'),
        ('vrrp_sync_group', 'G1', 'notify_fault', ['/etc/keepalived/fault.sh'], 'keepalived_script',
         'default:keepalived_script'),
    ]
    notify = next(p for p in r['programs'] if p['keyword'] == 'notify')
    assert notify['runtime_extra_args'] == 4 and notify['origin'] == 'not_assessed'


def test_default_user_follows_account_script_user_and_script_security():
    conf = 'vrrp_instance V {\n notify_stop /bin/stop\n}\n'
    found, r = progs(conf)
    assert not r['complete'] and r['gaps'][0]['code'] == 'default_user_unobserved'
    found, r = progs(conf, keepalived_script_exists=False)
    assert r['complete'] and found[0][4:] == ('root', 'default:daemon_user')
    _, r = progs('global_defs {\n enable_script_security\n}\n' + conf, keepalived_script_exists=False)
    assert r['programs'][0]['runs'] is False and r['programs'][0]['user'] is None
    # script_user only affects defaults looked up after it (set_default_script_user overwrites the cache).
    found, r = progs(conf + 'global_defs {\n script_user svc grp\n}\n' + conf.replace(' V ', ' W '),
                     keepalived_script_exists=True)
    assert [f[4] for f in found] == ['keepalived_script', 'svc']
    assert r['programs'][1]['group'] == 'grp'


def test_unknown_keyword_brace_rebinds_and_fails_closed():
    # 2.2.8: "Unknown keyword", then "Unexpected '{' - ignoring"; its "}" closes vrrp_instance, so
    # notify_master is then an unknown root keyword and never runs.
    conf = 'vrrp_instance V {\n bogus {\n x\n }\n notify_master /bin/late\n}\n'
    found, r = progs(conf, keepalived_script_exists=True)
    assert found == [] and not r['complete']
    codes = [g['code'] for g in r['gaps']]
    assert codes == ['unknown_keyword', 'unexpected_brace', 'unknown_keyword', 'unknown_keyword', 'unbalanced_brace']


def test_duplicate_instance_is_skipped_and_vrrp_script_last_script_wins():
    conf = ('vrrp_instance V {\n notify /bin/a\n}\nvrrp_instance V {\n notify /bin/b\n}\n'
            'vrrp_script s {\n script /bin/one\n script /bin/two\n user u\n}\nvrrp_script empty {\n interval 1\n}\n')
    found, r = progs(conf, keepalived_script_exists=False)
    assert r['complete']
    assert [f[3] for f in found] == [['/bin/a'], ['/bin/two']]


def test_checker_blocks_are_skipped_by_brace_count_and_reported_as_unmodelled():
    conf = ('virtual_server 192.0.2.1 80 {\n real_server 10.0.0.1 80 {\n MISC_CHECK {\n misc_path /bin/c\n }\n }\n'
            ' notify_up "/bin/up {"\n}\nvrrp_instance V {\n notify /bin/n\n}\n')
    found, r = progs(conf, keepalived_script_exists=False)
    assert [f[3] for f in found] == [['/bin/n']]
    assert [g['code'] for g in r['gaps']] == ['checker_not_modelled'] and not r['complete']


def test_structural_errors_are_blocking():
    for conf, code in (('vrrp_instance V\n notify /bin/x\n}\n', 'missing_brace'),
                       ('vrrp_instance V {\n virtual_ipaddress\n 192.0.2.1\n }\n}\n', 'missing_brace'),
                       ('vrrp_instance V {\n notify /bin/x\n', 'unterminated_block'),
                       ('vrrp_instance {\n notify /bin/x\n}\n', 'unnamed_block'),
                       ('garp_group {\n interfaces {\n eth0\n }\n}\n', 'unmodelled_nested_block'),
                       ('global_defs {\n startup_script /bin/s\n}\n', 'global_script_not_modelled'),
                       ('}\n', 'unbalanced_brace')):
        r = ks.vrrp_programs(conf, keepalived_script_exists=False)
        assert not r['complete'] and code in [g['code'] for g in r['gaps']], (conf, r['gaps'])


def test_value_block_on_one_line_and_preprocessing_gaps_carry_through():
    found, r = progs('vrrp_instance V { virtual_ipaddress { 192.0.2.1 } notify /bin/n }\n',
                     keepalived_script_exists=False)
    assert r['complete'] and [f[3] for f in found] == [['/bin/n']]
    r = ks.vrrp_programs('include /etc/keepalived/*.conf\n', keepalived_script_exists=False)
    assert not r['complete'] and r['gaps'][0]['code'] == 'include'
