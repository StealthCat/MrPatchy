from app import sshd_commands as sc

MAIN = '/etc/ssh/sshd_config'
DROP = '/etc/ssh/sshd_config.d/*.conf'


def run(text, extra=None, globs=None, version='9.2p1'):
    files = {MAIN: text, **(extra or {})}
    return sc.resolve(files, globs or {}, version=version)


def cmd(result, kind):
    return next(c for c in result['commands'] if c['kind'] == kind)


def test_authorized_keys_command_runs_as_its_user_with_percent_tokens():
    r = run('AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys %u\nAuthorizedKeysCommandUser nobody\n')
    akc = cmd(r, 'authorized_keys_command')
    assert r['status'] == 'complete' and r['origin'] == 'not_assessed'
    assert akc['runs'] and akc['run_as'] == 'nobody'
    assert akc['argv'] == ['/usr/bin/sss_ssh_authorizedkeys', '%u'] and akc['percent_tokens'] == ['u']
    assert akc['source'] == {'path': MAIN, 'line': 1}


def test_keyword_case_equals_and_first_value_wins():
    r = run('authorizedkeyscommand=/a\nAuthorizedKeysCommand /b\nAuthorizedKeysCommandUser = root\n'
            'AuthorizedKeysCommandUser nobody\n')
    akc = cmd(r, 'authorized_keys_command')
    assert akc['command'] == '/a' and akc['run_as'] == 'root'


def test_missing_command_user_stops_sshd_at_startup_but_only_skips_in_match():
    r = run('AuthorizedKeysCommand /a %u\n')
    assert r['status'] == 'config_error' and 'without AuthorizedKeysCommandUser' in r['config_error']
    assert run('AuthorizedKeysCommand none\n')['status'] == 'complete'
    r = run('Match User x\n AuthorizedKeysCommand /a %u\n')
    assert r['status'] == 'complete'
    assert r['conditional'][0]['commands'][0]['reason'] == 'no_command_user'


def test_relative_authentication_command_stops_sshd_even_inside_match():
    r = run('Match User x\n  AuthorizedKeysCommand bin/keys\n')
    assert r['status'] == 'config_error' and 'absolute' in r['config_error']
    assert not r['commands']


def test_none_and_unknown_percent_token_do_not_run():
    r = run('AuthorizedKeysCommand none\nAuthorizedKeysCommandUser nobody\n')
    assert cmd(r, 'authorized_keys_command')['reason'] == 'none'
    r = run('AuthorizedKeysCommand /a %i\nAuthorizedKeysCommandUser nobody\n')
    assert cmd(r, 'authorized_keys_command')['reason'] == 'invalid_percent_token'
    r = run('AuthorizedPrincipalsCommand /p %i %s\nAuthorizedPrincipalsCommandUser nobody\n')
    assert cmd(r, 'authorized_principals_command')['percent_tokens'] == ['i', 's']


def test_principals_command_gate_differs_between_versions():
    text = 'AuthorizedKeysCommand /k\nAuthorizedKeysCommandUser k\nAuthorizedPrincipalsCommand /p1\nAuthorizedPrincipalsCommandUser nobody\n'
    assert cmd(run(text), 'authorized_principals_command')['reason'] == 'not_set'
    assert cmd(run(text, version='9.6p1'), 'authorized_principals_command')['command'] == '/p1'
    # Before any AuthorizedKeysCommand, 9.2p1 keeps replacing the principals command.
    later = 'AuthorizedPrincipalsCommand /p1\nAuthorizedPrincipalsCommand /p2\nAuthorizedPrincipalsCommandUser u\n'
    assert cmd(run(later), 'authorized_principals_command')['command'] == '/p2'
    assert cmd(run(later, version='9.6p1'), 'authorized_principals_command')['command'] == '/p1'


def test_force_command_keeps_raw_text_and_none_clears():
    r = run('ForceCommand   internal-sftp -d /srv   \n')
    fc = cmd(r, 'force_command')
    assert fc['command'] == 'internal-sftp -d /srv' and fc['run_as'] == 'authenticating_user'
    assert cmd(run('ForceCommand NONE\n'), 'force_command')['reason'] == 'cleared_by_none'


def test_include_relative_sorted_globs_and_match_ends_at_file_end():
    drop_a = '/etc/ssh/sshd_config.d/a.conf'
    drop_b = '/etc/ssh/sshd_config.d/b.conf'
    r = run('Include sshd_config.d/*.conf\nAuthorizedKeysCommandUser nobody\n',
            {drop_b: 'AuthorizedKeysCommand /b\n', drop_a: 'Match User git\n ForceCommand /git\n'},
            {DROP: [drop_b, drop_a]})
    assert r['files_read'] == [MAIN, drop_a, drop_b]
    assert cmd(r, 'authorized_keys_command')['command'] == '/b'
    assert cmd(r, 'force_command')['reason'] == 'not_set'
    (block,) = r['conditional']
    assert block['conditions'] == [[['user', 'git']]] and block['path'] == drop_a
    assert block['commands'][0]['command'] == '/git'


def test_match_all_overrides_startup_and_shadows_later_blocks():
    r = run('ForceCommand /global\nMatch all\n ForceCommand /all\nMatch User x\n ForceCommand /x\n')
    assert cmd(r, 'force_command')['command'] == '/all'
    (block,) = r['conditional']
    assert block['overridden_fields'] == ['force_command']
    assert block['commands'][0]['command'] == '/all'


def test_include_inside_match_is_conditional_on_both():
    inner = '/etc/ssh/inner.conf'
    r = run('Match Group sftp\n Include /etc/ssh/inner.conf\n', {inner: 'ForceCommand /a\nMatch User u\nForceCommand /b\n'},
            {inner: [inner]})
    conds = [b['conditions'] for b in r['conditional']]
    assert conds == [[[['group', 'sftp']]], [[['group', 'sftp']], [['user', 'u']]]]
    assert r['conditional'][1]['overridden_fields'] == ['force_command']


def test_global_only_directive_in_match_stops_sshd():
    r = run('Match User x\n Port 2222\n')
    assert r['status'] == 'config_error' and 'not allowed within a Match block' in r['config_error']


def test_subsystem_rules_per_version():
    text = 'Subsystem sftp /usr/lib/openssh/sftp-server\nSubsystem sftp /other\n'
    assert run(text)['status'] == 'config_error'
    r = run(text, version='9.6p1')
    assert [s['argv'] for s in r['subsystems']] == [['/usr/lib/openssh/sftp-server']]
    assert run('Match User x\n Subsystem sftp internal-sftp\n')['status'] == 'config_error'
    r = run('Subsystem sftp /s\nMatch User x\n Subsystem sftp internal-sftp\n', version='9.6p1')
    assert r['subsystems'][0]['argv'] == ['/s']
    assert r['conditional'][0]['subsystems'][0]['reason'] == 'in_process_sftp'


def test_bad_options_quotes_and_match_syntax():
    assert run('AuthorizedKeysCommand "/a\n')['status'] == 'config_error'
    assert run('ForceCommand\n')['status'] == 'config_error'
    assert run('Match all User x\n')['status'] == 'config_error'
    assert run('Match Shell x\n')['status'] == 'config_error'
    assert run('Match User\n')['status'] == 'config_error'
    r = run('# comment\n\n   \nDebianBanner no\n')
    assert r['status'] == 'complete' and r['gaps'][0]['reason'] == 'unrecognized_keyword'


def test_runtime_argv_split_keeps_comment_text():
    akc = cmd(run('AuthorizedKeysCommand /a "x y" \\"z # c\nAuthorizedKeysCommandUser n\n'), 'authorized_keys_command')
    assert akc['argv'] == ['/a', 'x y', '"z', '#', 'c']


def test_fail_closed_inputs():
    assert sc.resolve({})['status'] == 'incomplete'
    assert sc.resolve({MAIN: b'\xff'})['gaps'][0]['reason'] == 'invalid_utf8'
    assert sc.resolve({MAIN: 'ForceCommand /a\0'})['gaps'][0]['reason'] == 'binary'
    assert sc.resolve({MAIN: 'x' * (sc.MAX_TEXT + 1)})['gaps'][0]['reason'] == 'over_limit'
    r = run('Include sshd_config.d/*.conf\n')
    assert r['status'] == 'incomplete' and r['gaps'][0] == {'reason': 'glob_not_observed', 'path': DROP}
    assert sc.resolve({MAIN: ''}, version='8.9p1')['status'] == 'incomplete'
    assert run('Include ~/x\n')['gaps'][0]['reason'] == 'home_relative_include'


def test_recursive_include_stops_sshd():
    r = run('Include /etc/ssh/sshd_config\n', globs={MAIN: [MAIN]})
    assert r['status'] == 'config_error' and 'recursive' in r['config_error']


def test_digest_is_stable():
    text = 'ForceCommand /a\n'
    assert run(text)['digest'] == run(text)['digest'] != run('ForceCommand /b\n')['digest']


def test_match_lines_in_one_file_do_not_nest():
    r = run('Match User a\nMatch all\n AuthorizedPrincipalsCommand /p %i\n')
    assert r['status'] == 'config_error' and 'without AuthorizedPrincipalsCommandUser' in r['config_error']
    r = run('Match User a\n ForceCommand /a\nMatch User b\n ForceCommand /b\n')
    assert [b['conditions'] for b in r['conditional']] == [[[['user', 'a']]], [[['user', 'b']]]]


def test_missing_or_empty_command_user_stops_sshd_even_in_match():
    for user in ('#x', '""'):
        for key in ('AuthorizedKeysCommandUser', 'AuthorizedPrincipalsCommandUser'):
            for text in ('AuthorizedKeysCommand /bin/k %%u\n%s %s\n' % (key, user),
                         'Match User x\n %s %s\n' % (key, user)):
                r = run(text)
                assert r['status'] == 'config_error' and 'missing %s argument' % key in r['config_error']
                assert not r['commands']


def test_forced_internal_sftp_runs_in_process():
    for value in ('internal-sftp', 'internal-sftp -R', 'internal-sftp\t-d /x'):
        assert cmd(run('ForceCommand %s\n' % value), 'force_command')['reason'] == 'in_process_sftp'
    for value in ('internal-sftpx', '/usr/lib/openssh/sftp-server'):
        assert cmd(run('ForceCommand %s\n' % value), 'force_command')['reason'] == 'runs_through_login_shell'
