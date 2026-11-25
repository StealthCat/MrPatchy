"""Pure OpenVPN script and plugin contract (#1361)."""
import pytest

from app import openvpn_scripts as ov

SRV = '/etc/openvpn/server'


def run_server(conf, files=None, instance='s'):
    args, cwd = ov.unit_arguments('openvpn-server@', instance)
    return ov.evaluate(args=args, files={SRV + '/' + instance + '.conf': conf, **(files or {})},
                       working_directory=cwd)


def run_legacy(conf, files=None, instance='vpn'):
    args, cwd = ov.unit_arguments('openvpn@', instance)
    return ov.evaluate(args=args, files={'/etc/openvpn/' + instance + '.conf': conf, **(files or {})},
                       working_directory=cwd)


def by_option(result):
    return {s['option']: s for s in result['scripts']}


def test_server_unit_default_script_security_refuses_user_scripts():
    r = run_server('dev tun\nup ./up.sh\n')
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed'
    assert r['script_security'] == 1
    [up] = r['scripts']
    assert up['executable'] == SRV + '/up.sh' and up['argv'] == ['./up.sh']
    assert up['permitted'] is False and 'refuses' in up['permission']
    assert up['may_run_as'] == [{'user': 'root', 'group': None}]


def test_legacy_unit_passes_script_security_two_and_config_can_override():
    r = run_legacy('up /etc/openvpn/up.sh\n')
    assert r['script_security'] == 2 and r['scripts'][0]['permitted'] is True
    r = run_legacy('script-security 0\nup /etc/openvpn/up.sh\n')
    assert r['script_security'] == 0 and r['scripts'][0]['permitted'] is False


def test_tokenizer_quotes_backslashes_comments_and_doubledash():
    conf = ('# comment\n; other\n--down "/usr/local/bin/down hook \\"q\\" \'x y\'"   # trailing\n'
            "route-up '/opt/r\\un a'\n")
    s = by_option(run_server(conf))
    assert s['down']['command'] == '/usr/local/bin/down hook "q" \'x y\''
    assert s['down']['argv'] == ['/usr/local/bin/down', 'hook', 'q', 'x y']
    assert s['route-up']['command'] == '/opt/r\\un a'
    assert s['route-up']['argv'] == ['/opt/r\\un a']  # bad backslash: whole string is the program


def test_parse_line_mirrors_openvpn_errors():
    assert ov.parse_line(b'up "unterminated\n') is None
    assert ov.parse_line(b"up 'unterminated\n") is None
    assert ov.parse_line(b'up \\a\n') is None
    assert ov.parse_line(b'up a\\ b\n') == [b'up', b'a b']
    assert ov.parse_line(b'a b#c ;d\n') == [b'a', b'b#c']
    assert ov.parse_line(b' '.join(b'x%d' % i for i in range(20)) + b'\n') == [b'x%d' % i for i in range(16)]


@pytest.mark.parametrize('line', [
    'up "/bin/x\n', 'up a b\n', 'up\n', 'auth-user-pass-verify /bin/a\n', 'auth-user-pass-verify /bin/a env\n',
    'tls-crypt-v2-verify a b\n', 'down-pre yes\n', 'script-security\n', 'user a b\n', '<up>\n/bin/x\n</up>\n',
    '<connection>\nremote x\n', 'up /bin/' + 'x' * 260 + '\n', 'config /etc/openvpn/server/s.conf\n',
])
def test_fatal_option_errors_report_config_error(line):
    r = run_server(line)
    assert r['status'] == 'config_error' and r['scripts'] == [] and r['plugins'] == []


def test_line_length_limit_is_exact():
    ok = 'up /' + 'x' * (ov.OPTION_LINE_SIZE - 6) + '\n'
    assert len(ok) == ov.OPTION_LINE_SIZE - 1 and run_server(ok)['status'] == 'loads'
    assert run_server(ok[:-1] + 'x\n')['status'] == 'config_error'


def test_inline_blocks_are_skipped_and_later_options_apply():
    conf = 'up /bin/a\n<ca>\n-----BEGIN-----\nup /bin/evil\n  </ca>\nup /bin/b\n'
    r = run_server(conf)
    assert r['status'] == 'loads' and r['scripts'][0]['command'] == '/bin/b'
    assert r['overridden'][0]['option'] == 'up' and r['scripts'][0]['source']['line'] == 6


def test_cd_and_nested_config_change_relative_paths():
    r = run_server('cd /srv/vpn\nconfig extra.conf\n', files={'/srv/vpn/extra.conf': 'cd sub\nlearn-address la.sh\n'})
    assert r['files_read'] == [SRV + '/s.conf', '/srv/vpn/extra.conf'] and r['complete']
    assert by_option(r)['learn-address']['executable'] == '/srv/vpn/sub/la.sh'


def test_recursive_include_stops_openvpn():
    r = ov.evaluate(args=['--config', '/a.conf'], files={'/a.conf': 'config /a.conf\n'}, working_directory='/')
    assert r['status'] == 'config_error' and 'recursive' in r['config_error']


def test_user_drop_identities_and_up_restart():
    r = run_legacy('user nobody\ngroup nogroup\nup /bin/u\ndown /bin/d\n')
    s = by_option(r)
    drop = {'user': 'nobody', 'group': 'nogroup'}
    assert r['privilege_drop'] == drop and s['up']['may_run_as'] == [{'user': 'root', 'group': None}]
    assert s['down']['may_run_as'] == [{'user': 'root', 'group': None}, drop]
    s = by_option(run_legacy('group nogroup\nup-restart\nup /bin/u\n'))
    assert s['up']['may_run_as'][1] == {'user': 'root', 'group': 'nogroup'} and 'restart' in s['up']['event']


def test_comma_substitution_and_auth_methods():
    s = by_option(run_legacy('script-security 3\ntls-verify /bin/v,arg\nipchange /bin/i,x\n'
                             'auth-user-pass-verify /bin/auth via-env\n'))
    assert s['tls-verify']['argv'] == ['/bin/v', 'arg'] and s['ipchange']['command'] == '/bin/i x'
    assert s['auth-user-pass-verify']['method'] == 'via-env'
    assert s['auth-user-pass-verify']['password_in_environment'] is True
    s = by_option(run_legacy('auth-user-pass-verify /bin/auth via-env\n'))
    assert s['auth-user-pass-verify']['password_in_environment'] is False


def test_plugins_load_as_root_regardless_of_script_security():
    conf = ('script-security 0\nplugin openvpn-plugin-down-root.so "/sbin/ip route del x"\n'
            'plugin ./local.so\nplugin /opt/p.so a b\n')
    r = run_server(conf)
    paths = [p['path'] for p in r['plugins']]
    assert paths == [ov.DEFAULT_PLUGIN_LIBDIR + '/openvpn-plugin-down-root.so', SRV + '/local.so', '/opt/p.so']
    assert r['plugins'][0]['root_command_arguments'] == ['/sbin/ip route del x']
    assert all(p['loads_as'] == {'user': 'root', 'group': None} for p in r['plugins'])


def test_fail_closed_inputs():
    assert run_server(None)['gaps'][0]['code'] == 'file_not_observed'
    for data, code in ((b'up /x\0\n', 'binary'), (b'up /\xff\n', 'invalid_utf8'),
                       (b'#' * (ov.MAX_TEXT + 1), 'over_limit')):
        r = run_server(data)
        assert not r['complete'] and r['gaps'][0]['code'] == code
    r = run_server('chroot /var/jail\nup /bin/u\n')
    assert not r['complete'] and r['gaps'][0]['code'] == 'chroot_paths'
    r = ov.evaluate(args=['--config', 'stdin'], files={}, working_directory='/')
    assert not r['complete'] and r['gaps'][0]['code'] == 'stdin_config'


def test_bom_single_argument_and_argv_errors():
    r = ov.evaluate(args=['/etc/x.conf'], files={'/etc/x.conf': '\ufeffup /bin/u\n'}, working_directory='/')
    assert r['scripts'][0]['command'] == '/bin/u'
    r = ov.evaluate(args=['--verb', '3', 'stray', '--config', '/x'], files={}, working_directory='/')
    assert r['status'] == 'loads'  # 'stray' is a --verb parameter
    r = ov.evaluate(args=['stray', '--config', '/x'], files={}, working_directory='/')
    assert r['status'] == 'config_error'
    with pytest.raises(ValueError):
        ov.unit_arguments('openvpn-server@', '../x')


def test_setenv_opt_prefix_registers_scripts_and_plugins():
    # options.c add_option strips 'setenv opt' and handles the rest as a normal option.
    r = run_server('setenv opt script-security 2\nsetenv opt up /tmp/evil\nsetenv opt plugin /tmp/evil.so\n'
                   'setenv opt user nobody\n')
    assert r['status'] == 'loads' and r['complete'] and r['script_security'] == 2
    [up] = r['scripts']
    assert up['executable'] == '/tmp/evil' and up['permitted'] is True
    assert [p['path'] for p in r['plugins']] == ['/tmp/evil.so']
    assert r['privilege_drop']['user'] == 'nobody'
    assert run_server('setenv opt cd /tmp\nsetenv opt up ./x\n')['scripts'][0]['executable'] == '/tmp/x'
    r = run_server('setenv opt config /etc/openvpn/server/inc.conf\n',
                   {SRV + '/inc.conf': 'setenv opt tls-verify /bin/a,b\n'})
    assert r['scripts'][0]['argv'] == ['/bin/a', 'b']


def test_setenv_opt_on_the_command_line():
    r = ov.evaluate(args=['--setenv', 'opt', 'up', '/tmp/evil', '--setenv', 'opt', 'down-pre'],
                    files={}, working_directory='/')
    assert r['status'] == 'loads' and r['scripts'][0]['executable'] == '/tmp/evil'
    assert 'before the tunnel device closes' not in r['scripts'][0]['event']  # down-pre without down
    r = ov.evaluate(args=['--setenv', 'opt', 'down', '/bin/d', '--down-pre'], files={}, working_directory='/')
    assert r['scripts'][0]['event'] == 'before the tunnel device closes (down-pre)'


@pytest.mark.parametrize('conf', [
    'setenv opt up\nup /bin/x\n', 'setenv opt\nup /bin/x\n',
    'setenv opt down-pre yes\nup /bin/x\n', 'setenv opt user a b\nup /bin/x\n',
    'setenv opt tls-crypt-v2-verify a b\nup /bin/x\n', 'setenv opt plugin\nup /bin/x\n',
    'setenv FORWARD_COMPATIBLE 1\nup\nup /bin/x\n', 'setenv opt setenv FORWARD_COMPATIBLE 1\nuser a b\nup /bin/x\n',
    'ignore-unknown-option up\nup\nup /bin/x\n', 'ignore-unknown-option --cd\ncd a b\nup /bin/x\n',
])
def test_relaxed_arity_errors_are_ignored_warnings(conf):
    r = run_server(conf)
    assert r['status'] == 'loads' and r['complete']
    assert [s['executable'] for s in r['scripts']] == ['/bin/x']
    assert r['warnings'] and r['warnings'][0]['code'] == 'option_ignored'
    assert r['privilege_drop'] is None and r['working_directory'] == SRV


@pytest.mark.parametrize('conf', [
    # Errors outside add_option's final branch stay fatal after the prefix.
    'setenv opt up a b\n', 'setenv opt auth-user-pass-verify /bin/a env\n', 'setenv opt up "/bin/x\n',
    # Relaxation does not apply before it is enabled, or to other names.
    'up\nsetenv FORWARD_COMPATIBLE 1\n', 'setenv FORWARD_COMPATIBLE 0\nup\n', 'ignore-unknown-option down\nup\n',
    'setenv FORWARD_COMPATIBLE 1 x\nup\n',
])
def test_relaxation_keeps_other_errors_fatal(conf):
    r = run_server(conf)
    assert r['status'] == 'config_error' and r['scripts'] == []


def test_inline_flag_is_an_unrecognized_option():
    assert run_server('<up-restart>\n</up-restart>\n')['status'] == 'config_error'
    r = run_server('setenv FORWARD_COMPATIBLE 1\n<up-restart>\n</up-restart>\nup /bin/x\n')
    assert r['status'] == 'loads' and r['warnings'][0]['option'] == 'up-restart'
    assert run_server('setenv FORWARD_COMPATIBLE 1\n<up>\n/bin/x\n</up>\n')['status'] == 'config_error'
