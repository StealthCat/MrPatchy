"""Tests for the pure per-user shell startup contract (#1057)."""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from app import shell_user_startup as sus

ROOT_BASH = {'shell': '/bin/bash', 'uid': 0, 'gid': 0}
USER_BASH = {'shell': '/bin/bash', 'uid': 1000, 'gid': 1000, 'groups': []}
LISTED = {'state': 'listed'}


def f(mode=0o644, uid=1000, gid=1000):
    return {'type': 'file', 'mode': mode, 'uid': uid, 'gid': gid}


ABSENT = {'type': 'absent'}


def files(**kw):
    out = {name: ABSENT for name in sus.DOTFILES}
    for key, value in kw.items():
        out['.' + key] = value
    return out


def run(dotfiles, **kwargs):
    kwargs.setdefault('account', USER_BASH)
    kwargs.setdefault('family', 'debian')
    kwargs.setdefault('home', LISTED)
    return sus.evaluate(dotfiles, **kwargs)


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def login(result):
    return result['sessions']['login']


def test_login_chain_reads_first_existing_file_only():
    result = run(files(bash_profile=f(), bash_login=f(), profile=f(), bashrc=f(), bash_logout=f()))
    assert login(result)['file'] == '~/.bash_profile' and login(result)['state'] == 'reads'
    by = {rec['name']: rec for rec in result['files']}
    assert by['.bash_login']['reasons']['login']['code'] == 'not_reached'
    assert by['.profile']['reasons']['login']['code'] == 'not_reached'
    assert result['sessions']['interactive']['file'] == '~/.bashrc'
    assert result['sessions']['ssh_command']['file'] == '~/.bashrc'
    assert result['sessions']['logout']['file'] == '~/.bash_logout'
    assert by['.bashrc']['runs_in'] == ['interactive', 'ssh_command']
    assert result['complete'] is True and result['gaps'] == []


def test_missing_and_dangling_names_fall_through():
    dangling = {'type': 'symlink', 'link_target': '/nonexistent', 'target': None}
    result = run(files(bash_profile=dangling, profile=f()))
    assert login(result)['file'] == '~/.profile'
    by = {rec['name']: rec for rec in result['files']}
    assert by['.bash_profile']['dangling'] is True
    assert by['.bash_profile']['reasons']['login']['code'] == 'absent'


@pytest.mark.parametrize(('obs', 'code'), [
    (f(0o000), 'chain_stopped_unreadable'),
    ({'type': 'directory'}, 'chain_stopped_directory'),
    ({'type': 'symlink', 'target': {'type': 'directory'}}, 'chain_stopped_directory'),
])
def test_unreadable_or_directory_stops_the_bash_chain(obs, code):
    result = run(files(bash_login=obs, profile=f()))
    assert login(result) == {'state': 'error', 'file': '~/.bash_login', 'reason_code': code,
                             'reason': sus.REASONS[code]}
    by = {rec['name']: rec for rec in result['files']}
    assert by['.profile']['reasons']['login']['code'] == 'not_reached'
    assert by['.profile']['runs_in'] == []


def test_root_reads_mode_0000():
    result = run(files(bash_login=f(0o000, 0, 0), profile=f()), account=ROOT_BASH)
    assert login(result)['state'] == 'reads' and login(result)['file'] == '~/.bash_login'


@pytest.mark.parametrize(('mode', 'fuid', 'fgid', 'groups', 'expected'), [
    (0o600, 1000, 5, [], True),
    (0o060, 1000, 1000, [], False),  # owner class applies even when group would allow
    (0o640, 0, 1000, [], True),  # primary group
    (0o640, 0, 7, [7], True),  # supplied supplementary group
    (0o640, 0, 7, [], False),
    (0o604, 0, 7, [7], False),  # group class wins over other
    (0o644, 0, 7, None, True),  # group and other agree, so groups do not matter
    (0o640, 0, 7, None, None),
    (0o604, 0, 7, None, None),
])
def test_account_can_read_uses_one_class(mode, fuid, fgid, groups, expected):
    assert sus.account_can_read(mode, fuid, fgid, 1000, 1000, groups) is expected


def test_unknown_groups_are_blocking_and_leave_later_files_unresolved():
    acct = {'shell': '/bin/bash', 'uid': 1000, 'gid': 1000}
    result = run(files(bash_profile=f(0o640, 0, 7), profile=f()), account=acct)
    assert login(result)['state'] == 'unknown' and login(result)['reason_code'] == 'depends_on_groups'
    by = {rec['name']: rec for rec in result['files']}
    assert by['.profile']['reasons']['login']['code'] == 'unresolved'
    assert 'groups_not_observed' in codes(result) and result['complete'] is False


def test_special_file_is_unknown_and_blocking():
    result = run(files(bash_profile={'type': 'other'}, profile=f()))
    assert login(result)['state'] == 'unknown' and login(result)['reason_code'] == 'special_file'
    assert 'special_file' in codes(result) and result['complete'] is False


def test_no_files_means_no_session_files():
    result = run(files())
    assert all(s['state'] == 'none' and s['file'] is None for s in result['sessions'].values())
    assert result['complete'] is True


def test_absent_home_runs_nothing_and_rejects_contradictory_files():
    result = run({}, home={'state': 'absent'})
    assert all(s['state'] == 'none' for s in result['sessions'].values()) and result['complete'] is True
    result = run(files(profile=f()), home={'state': 'absent'})
    assert 'input_malformed' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('shell', ['/bin/sh', '/usr/bin/sh', '/bin/dash', '/usr/bin/dash', ''])
def test_posix_login_reads_only_profile(shell):
    acct = dict(USER_BASH, shell=shell)
    result = run(files(bash_profile=f(), profile=f(), bashrc=f(), bash_logout=f()), account=acct)
    assert result['shell_kind'] == 'posix'
    assert login(result) == {'state': 'reads', 'file': '~/.profile', 'reason_code': 'reads',
                             'reason': sus.REASONS['reads']}
    for kind in ('interactive', 'ssh_command', 'logout'):
        assert result['sessions'][kind]['state'] == 'none'
        assert result['sessions'][kind]['reason_code'] == 'not_used_by_shell'
    by = {rec['name']: rec for rec in result['files']}
    assert by['.bash_profile']['runs_in'] == [] and by['.bashrc']['runs_in'] == []


@pytest.mark.parametrize(('obs', 'code'), [(f(0o000, 0, 0), 'skipped_unreadable'),
                                           ({'type': 'directory'}, 'skipped_directory')])
def test_dash_silently_skips_unreadable_or_directory_profile(obs, code):
    result = run(files(profile=obs), account=dict(USER_BASH, shell='/bin/sh'))
    assert login(result)['state'] == 'skipped' and login(result)['reason_code'] == code


@pytest.mark.parametrize('shell', ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false'])
def test_no_login_shell_runs_nothing(shell):
    result = run(files(bash_profile=f(), bashrc=f()), account=dict(USER_BASH, shell=shell))
    assert all(s['reason_code'] == 'no_login_shell' for s in result['sessions'].values())
    assert all(rec['runs_in'] == [] for rec in result['files']) and result['complete'] is True


@pytest.mark.parametrize('shell', ['/bin/zsh', '/usr/bin/fish', 'bash', '/bin/../bin/bash', '/opt/bash'])
def test_other_shells_are_not_modelled(shell):
    result = run(files(bash_profile=f()), account=dict(USER_BASH, shell=shell))
    assert result['shell_kind'] == 'other'
    assert all(s['state'] == 'unknown' for s in result['sessions'].values())
    assert 'shell_not_modelled' in codes(result) and result['complete'] is False


@pytest.mark.parametrize(('kwargs', 'code'), [
    ({'family': None}, 'family_not_observed'),
    ({'family': 'arch'}, 'family_unsupported'),
    ({'family': 'rpm'}, 'family_not_modelled'),
    ({'account': None}, 'account_not_observed'),
    ({'account': {'shell': '/bin/bash', 'uid': -1, 'gid': 0}}, 'input_malformed'),
    ({'account': {'shell': '/bin/bash', 'uid': True, 'gid': 0}}, 'input_malformed'),
    ({'account': {'shell': '/bin/bash\n', 'uid': 0, 'gid': 0}}, 'input_malformed'),
    ({'account': {'shell': '/bin/bash', 'uid': 0, 'gid': 0, 'groups': ['x']}}, 'input_malformed'),
    ({'home': None}, 'home_not_observed'),
    ({'home': {'state': 'weird'}}, 'input_malformed'),
    ({'home': {'state': 'unreadable'}}, 'home_unreadable'),
])
def test_unobserved_or_malformed_context_is_blocking(kwargs, code):
    result = run(files(bash_profile=f()), **kwargs)
    assert code in codes(result) and result['complete'] is False
    assert all(s['state'] == 'unknown' for s in result['sessions'].values())


@pytest.mark.parametrize('obs', [
    None, {'type': 'nope'}, {'type': 'file'}, {'type': 'file', 'mode': 0o644, 'uid': 0},
    {'type': 'symlink'}, {'type': 'symlink', 'target': {'type': 'file', 'mode': 0o644}},
])
def test_missing_dotfile_metadata_is_blocking(obs):
    dotfiles = files()
    dotfiles['.bash_profile'] = obs
    result = run(dotfiles)
    assert login(result)['state'] == 'unknown' and result['complete'] is False


def test_unexpected_names_and_bad_container_are_malformed():
    result = run(dict(files(), **{'.zshrc': f()}))
    assert 'input_malformed' in codes(result) and result['complete'] is False
    assert 'input_malformed' in codes(run(['not', 'a', 'mapping']))


def test_input_is_not_mutated_and_result_is_not_a_verdict():
    dotfiles = files(bash_profile={'type': 'symlink', 'link_target': '/x', 'target': f()}, bashrc=f())
    snapshot = repr(dotfiles)
    result = run(dotfiles)
    assert repr(dotfiles) == snapshot
    assert result['origin'] == 'not_assessed' and 'not a safety verdict' in result['note']
    assert {rec['name']: rec for rec in result['files']}['.bash_profile']['link_target'] == '/x'


# --- Live comparison with the shells on this host ---------------------------------------------------------


def _observe(home: Path) -> dict:
    out = {}
    for name in sus.DOTFILES:
        path = home / name
        if path.is_symlink():
            try:
                st = path.stat()
            except OSError:
                out[name] = {'type': 'symlink', 'target': None}
                continue
            target = (f(st.st_mode & 0o7777, st.st_uid, st.st_gid) if path.is_file()
                      else {'type': 'directory' if path.is_dir() else 'other'})
            out[name] = {'type': 'symlink', 'target': target}
        elif not path.exists():
            out[name] = {'type': 'absent'}
        elif path.is_dir():
            out[name] = {'type': 'directory'}
        elif path.is_file():
            st = path.lstat()
            out[name] = f(st.st_mode & 0o7777, st.st_uid, st.st_gid)
        else:
            out[name] = {'type': 'other'}
    return out


def _read_by(argv, home, demote=None, env_extra=None, stdin=subprocess.DEVNULL):
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', **(env_extra or {})}
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=env, stdin=stdin,
                          preexec_fn=demote, check=False)
    return [line.split(' ', 1)[1] for line in proc.stdout.splitlines() if line.startswith('READ ')]


SCENARIOS = {
    'all': {'.bash_profile': 0o644, '.bash_login': 0o644, '.profile': 0o644, '.bashrc': 0o644,
            '.bash_logout': 0o644},
    'login_only': {'.bash_login': 0o644, '.profile': 0o644},
    'locked_login': {'.bash_login': 0o000, '.profile': 0o644, '.bashrc': 0o600},
    'profile_only': {'.profile': 0o644, '.bashrc': 0o644},
    'dir_profile': {'.bash_profile': 'dir', '.profile': 0o644},
    'dangling': {'.bash_profile': 'dangling', '.profile': 0o644},
}


@pytest.mark.skipif(not (shutil.which('bash') and shutil.which('dash') and hasattr(os, 'geteuid')
                         and os.geteuid() == 0 and Path('/etc/debian_version').exists()),
                    reason='needs Debian bash, dash and root')
@pytest.mark.parametrize('scenario', sorted(SCENARIOS))
def test_live_shells_match_contract_as_root_and_nobody(scenario):
    try:
        nobody = pwd.getpwnam('nobody')
    except KeyError:
        pytest.skip('no nobody account')
    home = Path(tempfile.mkdtemp(prefix='shellstart-', dir='/tmp'))
    try:
        home.chmod(0o755)
        for name, mode in SCENARIOS[scenario].items():
            path = home / name
            if mode == 'dir':
                path.mkdir()
            elif mode == 'dangling':
                path.symlink_to('/nonexistent-shellstart-target')
            else:
                path.write_text(f'echo "READ {name}"\n')
                os.chown(path, 0, 0)
                path.chmod(mode)
        observed = _observe(home)

        def demote():
            os.setgid(nobody.pw_gid)
            os.setgroups([nobody.pw_gid])
            os.setuid(nobody.pw_uid)

        accounts = [({'shell': '/bin/bash', 'uid': 0, 'gid': 0, 'groups': []}, None),
                    ({'shell': '/bin/bash', 'uid': nobody.pw_uid, 'gid': nobody.pw_gid, 'groups': []}, demote)]
        for account, pre in accounts:
            result = run(observed, account=account)
            assert result['complete'] is True, result['gaps']
            sessions = result['sessions']

            def expect(kind, sessions=sessions):
                session = sessions[kind]
                return [session['file'][2:]] if session['state'] == 'reads' else []

            # bash -l -c 'exit' runs the login file and, through the exit builtin, ~/.bash_logout.
            actual = _read_by(['bash', '-l', '-c', 'exit'], home, pre)
            assert actual == expect('login') + expect('logout'), (account, actual)
            actual = _read_by(['bash', '-c', 'true'], home, pre, {'SSH_CLIENT': '192.0.2.1 50000 22'},
                              stdin=subprocess.PIPE)
            assert actual == expect('ssh_command'), (account, actual)
            assert _read_by(['bash', '-c', 'true'], home, pre, stdin=subprocess.PIPE) == []

            posix = run(observed, account=dict(account, shell='/bin/sh'))
            want = [posix['sessions']['login']['file'][2:]] if posix['sessions']['login']['state'] == 'reads' else []
            assert _read_by(['dash', '-l', '-c', 'true'], home, pre) == want
    finally:
        shutil.rmtree(home, ignore_errors=True)
