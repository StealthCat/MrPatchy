"""keepalived script contract (#1307), against traced keepalived 2.2.8 semantics."""
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
                       ('garp_group {\n other {\n eth0\n }\n}\n', 'unmodelled_nested_block'),
                       ('global_defs {\n lvs_notify_fifo_script /bin/s\n}\n', 'checker_not_modelled'),
                       ('}\n', 'unbalanced_brace')):
        r = ks.vrrp_programs(conf, keepalived_script_exists=False)
        assert not r['complete'] and code in [g['code'] for g in r['gaps']], (conf, r['gaps'])


def test_value_block_on_one_line_and_preprocessing_gaps_carry_through():
    found, r = progs('vrrp_instance V { virtual_ipaddress { 192.0.2.1 } notify /bin/n }\n',
                     keepalived_script_exists=False)
    assert r['complete'] and [f[3] for f in found] == [['/bin/n']]
    r = ks.vrrp_programs('include /etc/keepalived/*.conf\n', keepalived_script_exists=False)
    assert not r['complete'] and r['gaps'][0]['code'] == 'include'


# --- Increment 3: global_defs scripts in the parent and the VRRP child, traced against keepalived 2.2.8 ------


def every(conf, **kw):
    r = ks.keepalived_programs(conf, **kw)
    return [(p['process'], p['keyword'], p['argv'], p['user'], p['runs']) for p in r['programs']], r


def test_parent_runs_startup_and_shutdown_with_its_own_default_user_order():
    # The VRRP child looks up the default for notify before script_user; the parent parses vrrp_instance
    # inactive, so its first lookup is startup_script, after script_user.
    conf = ('vrrp_instance V {\n notify /bin/n\n}\n'
            'global_defs {\n script_user svc\n startup_script "/bin/start --now"\n startup_script /bin/second\n'
            ' startup_script_timeout 30\n shutdown_script /bin/stop root\n}\n')
    found, r = every(conf, keepalived_script_exists=True)
    assert r['complete'], r['gaps']
    assert found == [('parent', 'startup_script', ['/bin/start', '--now'], 'svc', True),
                     ('parent', 'shutdown_script', ['/bin/stop'], 'root', True),
                     ('vrrp', 'notify', ['/bin/n'], 'keepalived_script', True)]
    assert r['programs'][0]['user_source'] == 'default:script_user'
    assert [p['keyword'] for p in ks.vrrp_programs(conf, keepalived_script_exists=True)['programs']] == ['notify']


def test_vrrp_child_runs_fifo_scripts_with_the_fifo_appended():
    conf = ('global_defs {\n notify_fifo /run/ka.fifo\n notify_fifo_script "/bin/fifo -v" svc\n'
            ' notify_fifo_script /bin/ignored\n vrrp_notify_fifo /run/v.fifo\n vrrp_notify_fifo_script /bin/vfifo\n}\n'
            'vrrp_instance V {\n state BACKUP\n}\n')
    found, r = every(conf, keepalived_script_exists=False, run_all_children=False)
    assert r['complete'], r['gaps']
    assert found == [('vrrp', 'notify_fifo_script', ['/bin/fifo', '-v'], 'svc', True),
                     ('vrrp', 'vrrp_notify_fifo_script', ['/bin/vfifo'], 'root', True),
                     ('checker', 'notify_fifo_script', ['/bin/fifo', '-v'], 'svc', False)]
    assert [(p['fifo'], p['runtime_extra_args']) for p in r['programs']] == [
        ('/run/ka.fifo', 1), ('/run/v.fifo', 1), ('/run/ka.fifo', 1)]
    assert r['programs'][-1]['not_run_reason'] == 'checker_process_not_started'


def test_fifo_script_needs_its_fifo_and_a_vrrp_fifo_naming_the_global_fifo_is_dropped():
    conf = ('global_defs {\n notify_fifo /run/ka.fifo\n vrrp_notify_fifo /run/ka.fifo\n'
            ' vrrp_notify_fifo_script /bin/vfifo\n notify_fifo_script /bin/g\n}\nvrrp_instance V {\n}\n')
    found, _ = every(conf, keepalived_script_exists=False, run_all_children=False)
    assert found == [('vrrp', 'notify_fifo_script', ['/bin/g'], 'root', True),
                     ('checker', 'notify_fifo_script', ['/bin/g'], 'root', False)]
    found, r = every('global_defs {\n vrrp_notify_fifo_script /bin/v\n}\nvrrp_instance V {\n}\n',
                     keepalived_script_exists=False, run_all_children=False)
    assert found == [('vrrp', 'vrrp_notify_fifo_script', ['/bin/v'], 'root', False)]
    assert r['programs'][0]['not_run_reason'] == 'no_fifo' and r['complete']


def test_default_user_refusal_is_sticky_and_frees_the_notify_slot():
    conf = ('global_defs {\n enable_script_security\n}\n'
            'vrrp_instance V {\n notify_master /bin/a\n notify_master /bin/b svc\n}\n'
            'global_defs {\n script_user later\n}\nvrrp_instance W {\n notify /bin/c\n}\n')
    found, r = every(conf, keepalived_script_exists=False)
    assert found == [('vrrp', 'notify_master', ['/bin/a'], None, False),
                     ('vrrp', 'notify_master', ['/bin/b'], 'svc', True),
                     ('vrrp', 'notify', ['/bin/c'], None, False)]
    assert r['programs'][2]['not_run_reason'] == 'default_user_refused'


def test_vrrp_child_starts_only_with_vrrp_config_or_all():
    conf = 'global_defs {\n notify_fifo /run/f\n notify_fifo_script /bin/f\n}\n'
    r = ks.keepalived_programs(conf, keepalived_script_exists=False)
    assert r['vrrp_process_starts'] is None and r['programs'][0]['runs'] is None and not r['complete']
    assert r['gaps'][0]['code'] == 'vrrp_process_start_unobserved'
    r = ks.keepalived_programs(conf, keepalived_script_exists=False, run_all_children=False)
    assert r['complete'] and r['programs'][0]['runs'] is False
    r = ks.keepalived_programs(conf, keepalived_script_exists=False, run_all_children=True)
    assert r['complete'] and r['programs'][0]['runs'] is True
    r = ks.keepalived_programs('static_ipaddress {\n 192.0.2.1/24 dev eth0\n}\n' + conf,
                               keepalived_script_exists=False)
    assert r['vrrp_process_starts'] is True and r['programs'][0]['runs'] is True


def test_parent_walk_adds_no_duplicate_structure_gaps():
    conf = 'bogus 1\nvrrp_instance V {\n nope 2\n}\nglobal_defs {\n startup_script ""\n}\n'
    r = ks.keepalived_programs(conf, keepalived_script_exists=False)
    assert [(g['code'], g['line']) for g in r['gaps']] == [
        ('unknown_keyword', 1), ('unknown_keyword', 3), ('unparsable_script', 6)]


LVS = '''global_defs {
    lvs_notify_fifo /run/lvs.fifo
    lvs_notify_fifo_script /bin/lvsfifo
}
virtual_server 192.0.2.1 80 {
    lb_kind DR
    quorum_up "/bin/qup 'a b'" svc
    quorum_up /ignored/second
    quorum_down /bin/qdown
    real_server 10.0.0.1 80 {
        notify_up /bin/up
        notify_down /bin/down ops
        HTTP_GET {
            url {
                path /
                status_code 200
            }
            connect_timeout 3
        }
        MISC_CHECK {
            misc_path "/bin/old"
            misc_path "/bin/misc -x"
            user nobody
        }
    }
    real_server 10.0.0.2 80 {
        SMTP_CHECK {
            host {
                connect_ip 10.0.0.2
            }
        }
        MISC_CHECK {
            misc_path /bin/misc2
        }
    }
}
'''


def test_checker_runs_quorum_notify_misc_and_lvs_fifo_scripts():
    found, r = every(LVS, keepalived_script_exists=False)
    assert r['complete'], r['gaps']
    assert r['checker_process_starts'] is True and r['vrrp_process_starts'] is None
    assert [f for f in found if f[0] == 'checker'] == [
        ('checker', 'quorum_up', ['/bin/qup', 'a b'], 'svc', True),
        ('checker', 'quorum_down', ['/bin/qdown'], 'root', True),
        ('checker', 'notify_up', ['/bin/up'], 'root', True),
        ('checker', 'notify_down', ['/bin/down'], 'ops', True),
        ('checker', 'misc_path', ['/bin/misc', '-x'], 'nobody', True),
        ('checker', 'misc_path', ['/bin/misc2'], 'root', True),
        ('checker', 'lvs_notify_fifo_script', ['/bin/lvsfifo'], 'root', True)]
    checker = [p for p in r['programs'] if p['process'] == 'checker']
    assert [p['block'] for p in checker[:5]] == ['virtual_server', 'virtual_server', 'real_server', 'real_server',
                                                 'MISC_CHECK']
    assert checker[2]['name'] == '10.0.0.1 80' and checker[2]['virtual_server'] == '192.0.2.1 80'
    assert checker[-1]['fifo'] == '/run/lvs.fifo'
    # vrrp_programs alone still flags the checker blocks it does not model.
    assert 'checker_not_modelled' in [g['code'] for g in ks.vrrp_programs(LVS, keepalived_script_exists=False)['gaps']]


def test_virtual_server_without_real_servers_or_with_a_mismatched_family_drops_scripts():
    conf = ('virtual_server 192.0.2.1 80 {\n quorum_up /bin/q\n real_server 2001:db8::1 80 {\n notify_up /bin/u\n'
            ' }\n}\nvirtual_server fwmark 7 {\n real_server 2001:db8::2 80 {\n lvs_method TUN\n notify_up /bin/t\n'
            ' }\n real_server 10.0.0.3 80 {\n notify_up /bin/v4\n }\n quorum_down /bin/qd\n}\n')
    found, r = every(conf, keepalived_script_exists=False)
    assert r['complete'], r['gaps']
    assert [(f[1], f[2][0], f[4]) for f in found] == [
        ('quorum_up', '/bin/q', False), ('notify_up', '/bin/u', False), ('notify_up', '/bin/t', True),
        ('notify_up', '/bin/v4', True), ('quorum_down', '/bin/qd', True)]
    assert [p['not_run_reason'] for p in r['programs'][:2]] == ['virtual_server_without_real_servers',
                                                                'real_server_family_mismatch']


def test_invalid_addresses_skip_blocks_and_uncertain_ones_fail_closed():
    conf = ('virtual_server 192.0.2.300 80 {\n quorum_up /bin/bad\n real_server 10.0.0.1 80 {\n notify_up /bin/x\n'
            ' }\n}\nvirtual_server 192.0.2.1 0 {\n real_server 10.0.0.1 99999 {\n notify_up /bin/y\n }\n'
            ' real_server 10.0.0.2 {\n notify_up /bin/z\n }\n}\n')
    found, r = every(conf, keepalived_script_exists=False)
    assert r['complete'], r['gaps']
    assert [f[2] for f in found] == [['/bin/z']]
    r = ks.keepalived_programs('virtual_server 192.0.2.1 +80 {\n real_server 10.0.0.1 80 {\n}\n}\n',
                               keepalived_script_exists=False)
    assert [g['code'] for g in r['gaps']] == ['address_unverified'] and not r['complete']


def test_misc_check_default_user_order_and_missing_path():
    conf = ('virtual_server 192.0.2.1 80 {\n real_server 10.0.0.1 80 {\n MISC_CHECK {\n user\n misc_timeout 5\n'
            ' }\n MISC_CHECK {\n misc_path /bin/m\n }\n }\n}\nglobal_defs {\n script_user svc\n}\n')
    found, r = every(conf, keepalived_script_exists=True)
    assert r['complete'], r['gaps']
    assert found == [('checker', 'misc_path', ['/bin/m'], 'keepalived_script', True)]
    found, r = every('global_defs {\n enable_script_security\n}\n' + conf.rsplit('global_defs', 1)[0],
                     keepalived_script_exists=False)
    assert found == [('checker', 'misc_path', ['/bin/m'], None, False)]
    assert r['programs'][0]['not_run_reason'] == 'default_user_refused'


def test_checker_skips_vrrp_roots_and_needs_virtual_server_or_all():
    conf = 'global_defs {\n lvs_notify_fifo /f\n lvs_notify_fifo_script /bin/l\n}\nvrrp_instance V {\n notify /bin/n\n}\n'
    found, r = every(conf, keepalived_script_exists=False)
    assert ('checker', 'lvs_notify_fifo_script', ['/bin/l'], 'root', None) in found
    assert 'checker_process_start_unobserved' in [g['code'] for g in r['gaps']] and not r['complete']
    found, r = every(conf, keepalived_script_exists=False, run_all_children=True)
    assert r['complete'] and ('checker', 'lvs_notify_fifo_script', ['/bin/l'], 'root', True) in found
    found, r = every(conf, keepalived_script_exists=False, run_all_children=False)
    assert r['complete'] and r['checker_process_starts'] is False
    assert ('checker', 'lvs_notify_fifo_script', ['/bin/l'], 'root', False) in found


def test_track_bfd_and_garp_roots_run_no_program_and_their_value_lists_are_values():
    conf = """
track_group TG {
  group {
    VI_1
    notify_master /tmp/not-a-script
  }
}
garp_group {
  garp_interval 1
  interfaces { eth0 notify /tmp/not-a-script }
  interface eth1
}
bfd_instance B {
  neighbor_ip 192.0.2.9
  weight 10
}
vrrp_track_process P {
  process nginx
  param_match initial
}
track_file F {
  file /run/f
  init_file 0 overwrite
}
vrrp_instance VI_1 {
  notify_master /bin/m
}
"""
    r = ks.vrrp_programs(conf, keepalived_script_exists=False)
    assert r['complete'], r['gaps']
    assert [(p['block'], p['argv']) for p in r['programs']] == [('vrrp_instance', ['/bin/m'])]


def test_repeated_track_group_list_fails_closed():
    conf = 'track_group TG {\n group {\n VI_1\n }\n group {\n VI_2\n }\n}\nvrrp_instance VI_1 {\n}\n'
    r = ks.vrrp_programs(conf, keepalived_script_exists=False)
    assert not r['complete'] and [g['code'] for g in r['gaps']] == ['unmodelled_nested_block']
