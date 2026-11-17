from app import ssh_rc

SHA = 'a' * 64
SYS_SHA = 'b' * 64
KNOWN = {'permit_user_rc': True, 'force_command': False, 'chroot_directory': False}


def present(kind='regular', sha=SHA):
    out = {'state': 'present', 'kind': kind}
    if sha and kind == 'regular':
        out['sha256'] = sha
    return out


ABSENT = {'state': 'absent'}


def account(**overrides):
    base = {'user': 'alice', 'home': '/home/alice', 'shell': '/bin/bash', 'user_rc': present(),
            'key_user_rc': 'permitted'}
    base.update(overrides)
    return base


def run(system_rc=None, sshd=None, accounts=None):
    return ssh_rc.resolve({'system_rc': present(sha=SYS_SHA) if system_rc is None else system_rc,
                           'sshd': KNOWN if sshd is None else sshd,
                           'accounts': [account()] if accounts is None else accounts})


def sessions(result, index=0):
    return result['accounts'][index]['sessions']


def test_user_rc_runs_through_login_shell_and_skips_system_rc():
    result = run()
    s = sessions(result)['session']
    assert result['complete'] is True and result['gaps'] == []
    assert s['outcome'] == 'user_rc'
    assert s['path'] == '/home/alice/.ssh/rc'
    assert s['command'] == "/bin/bash -c '/bin/sh /home/alice/.ssh/rc'"
    assert s['sha256'] == SHA and s['script_runs'] is True
    assert s['system_rc_skipped'] is True and s['xauth_left_to_rc'] is True


def test_empty_login_shell_defaults_to_bin_sh():
    s = sessions(run(accounts=[account(shell='')]))['session']
    assert s['command'] == "/bin/sh -c '/bin/sh /home/alice/.ssh/rc'"


def test_subsystem_session_runs_system_rc_not_user_rc():
    s = sessions(run())['subsystem']
    assert s['outcome'] == 'system_rc'
    assert s['command'] == '/bin/sh /etc/ssh/sshrc' and s['sha256'] == SYS_SHA
    assert 'subsystem_ignores_user_rc' in s['reasons']


def test_force_command_skips_user_rc_but_runs_system_rc():
    s = sessions(run(sshd={**KNOWN, 'force_command': True}))['session']
    assert s['outcome'] == 'system_rc'
    assert 'force_command_ignores_user_rc' in s['reasons']


def test_permit_user_rc_no_falls_back_to_system_rc():
    s = sessions(run(sshd={**KNOWN, 'permit_user_rc': False}))['session']
    assert s['outcome'] == 'system_rc' and 'permit_user_rc_no' in s['reasons']


def test_key_options_deny_user_rc():
    s = sessions(run(accounts=[account(key_user_rc='denied')]))['session']
    assert s['outcome'] == 'system_rc' and 'authentication_options_deny_user_rc' in s['reasons']


def test_absent_user_rc_falls_back_to_system_rc():
    s = sessions(run(accounts=[account(user_rc=ABSENT)]))['session']
    assert s['outcome'] == 'system_rc' and 'user_rc_absent' in s['reasons']


def test_neither_present_means_no_hook_and_sshd_handles_xauth():
    result = run(system_rc=ABSENT, accounts=[account(user_rc=ABSENT)])
    for kind in ('session', 'subsystem'):
        s = sessions(result)[kind]
        assert s['outcome'] == 'none' and s['xauth_left_to_rc'] is False
    assert result['complete'] is True


def test_user_rc_directory_blocks_system_rc_without_running_anything():
    s = sessions(run(accounts=[account(user_rc=present('directory'))]))['session']
    assert s['outcome'] == 'user_rc' and s['script_runs'] is False
    assert s['system_rc_skipped'] is True and 'user_rc_is_directory' in s['reasons']


def test_nologin_shell_takes_user_rc_branch_but_never_runs_the_script():
    for shell in ('/usr/sbin/nologin', '/bin/false'):
        s = sessions(run(accounts=[account(shell=shell)]))['session']
        assert s['outcome'] == 'user_rc' and s['script_runs'] is False
        assert 'login_shell_does_not_run_commands' in s['reasons']


def test_system_rc_directory_reported_as_not_running():
    s = sessions(run(system_rc=present('directory')))['subsystem']
    assert s['outcome'] == 'system_rc' and s['script_runs'] is False


def test_mixed_keys_report_each_alternative():
    s = sessions(run(accounts=[account(key_user_rc='mixed')]))['session']
    assert s['outcome'] == 'depends_on_key'
    assert s['by_key']['permitted']['outcome'] == 'user_rc'
    assert s['by_key']['denied']['outcome'] == 'system_rc'
    # The subsystem never uses the user rc, so key options do not matter there.
    assert sessions(run(accounts=[account(key_user_rc='mixed')]))['subsystem']['outcome'] == 'system_rc'


def test_unknown_key_permission_is_uncertain_with_gap():
    result = run(accounts=[account(key_user_rc='unknown')])
    s = sessions(result)['session']
    assert s['outcome'] == 'uncertain' and s['possible'] == ['system_rc', 'user_rc']
    assert result['complete'] is False
    assert {'code': 'input_unknown', 'user': 'alice', 'session': 'session', 'input': 'key_user_rc'} in result['gaps']
    # An unknown key option cannot change subsystem sessions.
    assert sessions(result)['subsystem']['outcome'] == 'system_rc'


def test_unknown_input_that_cannot_change_outcome_stays_resolved():
    # ForceCommand is unknown, but with no user rc the outcome is the system rc either way.
    result = run(sshd={**KNOWN, 'force_command': None}, accounts=[account(user_rc=ABSENT)])
    assert sessions(result)['session']['outcome'] == 'system_rc'
    assert result['complete'] is True


def test_unobserved_user_rc_is_a_gap_never_covered():
    result = run(accounts=[account(user_rc=None)])
    assert sessions(result)['session']['outcome'] == 'uncertain'
    assert result['complete'] is False
    assert any(g['code'] == 'user_rc_not_observed' for g in result['gaps'])


def test_unobserved_system_rc_is_a_gap():
    result = run(system_rc={'state': 'unknown'}, accounts=[account(user_rc=ABSENT)])
    assert sessions(result)['subsystem']['outcome'] == 'uncertain'
    assert any(g['code'] == 'system_rc_not_observed' for g in result['gaps'])


def test_chroot_directory_is_never_resolved():
    for value, code in ((True, 'chroot_paths_not_observed'), (None, 'chroot_directory_unknown')):
        result = run(sshd={**KNOWN, 'chroot_directory': value})
        assert sessions(result)['session']['outcome'] == 'uncertain'
        assert any(g['code'] == code for g in result['gaps'])
        assert result['complete'] is False


def test_match_override_applies_to_one_account_only():
    result = run(accounts=[account(), account(user='bob', home='/home/bob', sshd={'permit_user_rc': False})])
    assert sessions(result, 0)['session']['outcome'] == 'user_rc'
    assert sessions(result, 1)['session']['outcome'] == 'system_rc'


def test_home_with_whitespace_or_quote_is_unresolved():
    for home in ('/home/a b', "/home/o'neil"):
        result = run(accounts=[account(home=home)])
        s = sessions(result)['session']
        assert s['outcome'] == 'user_rc' and s['script_runs'] is None
        assert 'home_path_resplit_by_shell' in s['reasons']
        assert result['complete'] is False


def test_present_without_kind_is_unresolved_execution():
    result = run(accounts=[account(user_rc={'state': 'present'})])
    assert sessions(result)['session']['script_runs'] is None
    assert any(g['code'] == 'script_execution_unresolved' for g in result['gaps'])


def test_malformed_observations_fail_closed():
    assert ssh_rc.resolve('nope')['gaps'][0]['code'] == 'invalid_observation'
    assert ssh_rc.resolve({'extra': 1})['complete'] is False
    bad = ssh_rc.resolve({'system_rc': {'state': 'absent', 'sha256': SHA}, 'sshd': KNOWN, 'accounts': []})
    assert bad['complete'] is False and bad['accounts'] == []
    bad_sshd = ssh_rc.resolve({'system_rc': ABSENT, 'sshd': {'permit_user_rc': 'yes'}, 'accounts': []})
    assert bad_sshd['gaps'][0]['code'] == 'invalid_observation'


def test_invalid_and_duplicate_accounts_are_skipped_with_gaps():
    result = run(accounts=[account(), account(), account(user='x;rm', home='/h'), account(user='c', home='rel'),
                           account(user='d', home='/home/d', shell='bash'),
                           account(user='e', home='/home/e', key_user_rc='maybe')])
    assert [a['user'] for a in result['accounts']] == ['alice']
    assert [g['code'] for g in result['gaps']] == ['invalid_account'] * 5
    assert result['complete'] is False


def test_accounts_over_cap_reported():
    accounts = [account(user=f'u{i}', home=f'/home/u{i}', user_rc=ABSENT) for i in range(ssh_rc.MAX_ACCOUNTS + 1)]
    result = run(accounts=accounts)
    assert len(result['accounts']) == ssh_rc.MAX_ACCOUNTS
    assert result['gaps'][0]['code'] == 'accounts_over_cap' and result['complete'] is False


def test_hash_only_reported_for_regular_files():
    try:
        ssh_rc._file({'state': 'present', 'kind': 'directory', 'sha256': SHA})
    except ssh_rc.Invalid:
        pass
    else:
        raise AssertionError('hash accepted for a directory')


def test_unknown_permit_user_rc_is_uncertain_when_user_rc_exists():
    result = run(sshd={**KNOWN, 'permit_user_rc': None})
    s = sessions(result)['session']
    assert s['outcome'] == 'uncertain' and s['possible'] == ['system_rc', 'user_rc']
    assert 'permit_user_rc_unknown' in s['reasons'] and result['complete'] is False
