"""Tests for the pure zsh startup-file contract (#1371)."""
from __future__ import annotations

import pytest

from app import zsh_startup as zs

HOME = '/home/alice'
NAMES = ('zshenv', 'zprofile', 'zshrc', 'zlogin', 'zlogout')
USER = ('.zshenv', '.zprofile', '.zshrc', '.zlogin', '.zlogout')


def tree(global_dir='/etc/zsh', user_dir=HOME, **overrides):
    files = {}
    for name in NAMES:
        files[f'{global_dir}/{name}'] = {'type': 'file', 'mtime': 100, 'readable': True}
    for name in USER:
        files[f'{user_dir}/{name}'] = {'type': 'file', 'mtime': 100, 'readable': True}
    for path in list(files):
        files[path + '.zwc'] = {'type': 'absent'}
    files.update(overrides)
    return files


def run(argv0='zsh', options=(), interactive=False, family='debian', zdotdir=None, home=HOME, files=None,
        ids=None):
    return zs.evaluate({
        'family': family,
        'invocation': {'argv0': argv0, 'options': list(options), 'interactive': interactive},
        'ids': ids or {'uid': 1000, 'euid': 1000, 'gid': 1000, 'egid': 1000},
        'environment': {'HOME': home, 'ZDOTDIR': zdotdir},
        'files': tree(user_dir=zdotdir if zdotdir is not None else home) if files is None else files,
    })


def runs(result, phase=None):
    return [r['path'] for r in result['runs'] if phase is None or r['phase'] == phase]


def codes(result):
    return {g['code'] for g in result['gaps']}


def test_noninteractive_reads_only_zshenv_files():
    result = run()
    assert runs(result) == ['/etc/zsh/zshenv', f'{HOME}/.zshenv']
    assert result['session'] == 'noninteractive' and result['complete'] is True


def test_interactive_login_order_and_logout():
    result = run(argv0='-zsh', interactive=True)
    assert result['session'] == 'interactive_login'
    assert runs(result) == ['/etc/zsh/zshenv', f'{HOME}/.zshenv', '/etc/zsh/zprofile', f'{HOME}/.zprofile',
                            '/etc/zsh/zshrc', f'{HOME}/.zshrc', '/etc/zsh/zlogin', f'{HOME}/.zlogin',
                            f'{HOME}/.zlogout', '/etc/zsh/zlogout']
    assert runs(result, 'logout') == [f'{HOME}/.zlogout', '/etc/zsh/zlogout']


def test_login_option_without_dash_name():
    result = run(options=['-l', '-c'])
    assert runs(result) == ['/etc/zsh/zshenv', f'{HOME}/.zshenv', '/etc/zsh/zprofile', f'{HOME}/.zprofile',
                            '/etc/zsh/zlogin', f'{HOME}/.zlogin', f'{HOME}/.zlogout', '/etc/zsh/zlogout']


def test_interactive_non_login_reads_zshrc_not_profile():
    assert runs(run(options=['-i'], interactive=True)) == ['/etc/zsh/zshenv', f'{HOME}/.zshenv',
                                                            '/etc/zsh/zshrc', f'{HOME}/.zshrc']


def test_rpm_global_files_live_in_etc():
    files = tree(global_dir='/etc')
    assert runs(run(family='rpm', files=files)) == ['/etc/zshenv', f'{HOME}/.zshenv']


def test_no_rcs_leaves_only_global_zshenv():
    result = run(argv0='-zsh', options=['-f'], interactive=True)
    assert runs(result) == ['/etc/zsh/zshenv']
    assert {e['decision'] for e in result['sequence'][1:]} == {'skipped_no_rcs'}


def test_no_global_rcs_skips_later_global_files_only():
    result = run(argv0='-zsh', options=['--no-globalrcs'])
    assert runs(result) == ['/etc/zsh/zshenv', f'{HOME}/.zshenv', f'{HOME}/.zprofile', f'{HOME}/.zlogin',
                            f'{HOME}/.zlogout']


@pytest.mark.parametrize('ids,options', [({'uid': 1000, 'euid': 0, 'gid': 1000, 'egid': 1000}, []),
                                         ({'uid': 1000, 'euid': 1000, 'gid': 1000, 'egid': 0}, []),
                                         (None, ['-p'])])
def test_privileged_skips_user_files(ids, options):
    result = run(argv0='-zsh', options=options, ids=ids)
    assert result['privileged'] is True
    assert runs(result) == ['/etc/zsh/zshenv', '/etc/zsh/zprofile', '/etc/zsh/zlogin', '/etc/zsh/zlogout']


def test_zdotdir_replaces_home_and_empty_zdotdir_is_root():
    assert runs(run(zdotdir='/srv/z')) == ['/etc/zsh/zshenv', '/srv/z/.zshenv']
    assert runs(run(zdotdir='', files=tree(user_dir=''))) == ['/etc/zsh/zshenv', '/.zshenv']


def test_relative_zdotdir_is_blocking():
    result = run(zdotdir='z')
    assert 'zdotdir_relative' in codes(result) and result['complete'] is False
    assert runs(result) == ['/etc/zsh/zshenv']


@pytest.mark.parametrize('zwc_mtime,source,compiled', [(100, 'file', True), (200, 'file', True),
                                                        (99, 'file', False), (1, 'absent', True)])
def test_compiled_file_substitution(zwc_mtime, source, compiled):
    path = f'{HOME}/.zshenv'
    src = {'type': 'absent'} if source == 'absent' else {'type': 'file', 'mtime': 100, 'readable': True}
    result = run(files=tree(**{path: src, path + '.zwc': {'type': 'file', 'mtime': zwc_mtime}}))
    entry = result['sequence'][1]
    assert (entry['decision'] == 'reads_compiled') is compiled
    assert ('compiled_file_unverified' in codes(result)) is compiled
    assert result['complete'] is not compiled
    if compiled:
        assert result['runs'][1]['compiled'] == path + '.zwc'


def test_global_compiled_file_is_reported():
    result = run(files=tree(**{'/etc/zsh/zshenv.zwc': {'type': 'file', 'mtime': 500}}))
    assert result['runs'][0] == {'phase': 'env', 'path': '/etc/zsh/zshenv', 'compiled': '/etc/zsh/zshenv.zwc'}


@pytest.mark.parametrize('meta,decision', [({'type': 'absent'}, 'absent'),
                                           ({'type': 'directory', 'mtime': 1}, 'skipped_directory'),
                                           ({'type': 'file', 'mtime': 1, 'readable': False}, 'skipped_unreadable')])
def test_silent_skips(meta, decision):
    result = run(files=tree(**{f'{HOME}/.zshenv': meta}))
    assert result['sequence'][1]['decision'] == decision
    assert result['complete'] is True and runs(result) == ['/etc/zsh/zshenv']


def test_special_file_is_blocking():
    result = run(files=tree(**{f'{HOME}/.zshenv': {'type': 'other', 'mtime': 1}}))
    assert result['sequence'][1]['decision'] == 'special_file'
    assert 'special_file' in codes(result) and result['complete'] is False


def test_long_zdotdir_path_is_too_long():
    zdotdir = '/' + 'a' * (zs.PATH_MAX - 8)
    result = run(zdotdir=zdotdir, files=tree(user_dir=zdotdir))
    assert result['sequence'][1]['decision'] == 'path_too_long'


@pytest.mark.parametrize('argv0,emulation', [('sh', 'sh'), ('-sh', 'sh'), ('/bin/ksh', 'ksh'), ('bzsh', 'sh'),
                                             ('rsh', 'sh'), ('rzsh', 'zsh'), ('csh', 'zsh'), ('-zsh', 'zsh'),
                                             ('/usr/bin/zsh5', 'zsh')])
def test_emulation_from_invoked_name(argv0, emulation):
    assert zs.emulation_for(argv0) == emulation
    result = run(argv0=argv0)
    assert result['emulation'] == emulation
    assert ('emulation_not_modelled' in codes(result)) is (emulation != 'zsh')
    if emulation != 'zsh':
        assert result['runs'] == [] and result['complete'] is False


def test_unknown_option_is_blocking():
    result = run(options=['-o', 'norcs'])
    assert 'options_unverified' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('payload,code', [
    ({'family': 'debian'}, 'invocation_not_observed'),
    ({'invocation': {'argv0': 'zsh', 'options': [], 'interactive': False}}, 'family_not_observed'),
    ({'family': 'arch', 'invocation': {'argv0': 'zsh', 'options': [], 'interactive': False}}, 'family_unsupported'),
    ({'family': 'debian', 'invocation': {'argv0': 'zsh', 'options': [], 'interactive': False},
      'environment': {'HOME': HOME}}, 'zdotdir_not_observed'),
    ({'family': 'debian', 'invocation': {'argv0': 'zsh', 'options': ['-i'], 'interactive': False}}, 'input_malformed'),
    ({'family': 'debian', 'invocation': {'argv0': 'zsh', 'options': [], 'interactive': 'yes'}}, 'input_malformed'),
    ('nope', 'input_malformed'),
])
def test_malformed_or_unobserved_input_is_blocking(payload, code):
    result = zs.evaluate(payload)
    assert code in codes(result) and result['complete'] is False


def test_missing_ids_leave_user_files_unresolved():
    result = zs.evaluate({'family': 'debian', 'invocation': {'argv0': 'zsh', 'options': [], 'interactive': False},
                          'environment': {'HOME': HOME, 'ZDOTDIR': None}, 'files': tree()})
    assert 'ids_not_observed' in codes(result)
    assert result['sequence'][1]['decision'] == 'unresolved' and result['complete'] is False


def test_unobserved_file_is_blocking():
    files = tree()
    del files[f'{HOME}/.zshenv.zwc']
    result = run(files=files)
    assert 'file_not_observed' in codes(result) and result['sequence'][1]['decision'] == 'unresolved'
    assert result['complete'] is False


def test_unset_zdotdir_without_home_is_blocking():
    result = run(home=None)
    assert 'home_not_observed' in codes(result) and result['complete'] is False


def test_gap_list_is_bounded():
    gaps: list = []
    for i in range(60):
        zs._gap(gaps, 'file_not_observed', f'/p{i}')
    assert len(gaps) == zs.MAX_GAPS and gaps[-1]['code'] == 'gaps_truncated'
    assert 'gaps_truncated' in zs.BLOCKING


def test_contents_limit_is_disclosed_and_no_verdict():
    result = run()
    assert any('contents are not read' in line for line in result['unobserved'])
    assert 'not a safety verdict' in result['note']


SCRIPT_DIRS = ['/usr/share/zsh/scripts', '/usr/share/zsh/5.9/scripts']
SITE_NEWUSER, VERSION_NEWUSER = (f'{d}/newuser' for d in SCRIPT_DIRS)


def fresh_tree(**overrides):
    """No user startup files; both newuser candidates observed, only the versioned one present."""
    files = tree()
    for name in USER:
        files[f'{HOME}/{name}'] = {'type': 'absent'}
    files.update({SITE_NEWUSER: {'type': 'absent'}, SITE_NEWUSER + '.zwc': {'type': 'absent'},
                  VERSION_NEWUSER: {'type': 'file', 'mtime': 100, 'readable': True},
                  VERSION_NEWUSER + '.zwc': {'type': 'absent'}})
    files.update(overrides)
    return files


def run_new(options=('-i',), files=None, newuser=None, ids=None, argv0='zsh'):
    return zs.evaluate({
        'family': 'debian',
        'invocation': {'argv0': argv0, 'options': list(options), 'interactive': True},
        'ids': ids or {'uid': 1000, 'euid': 1000, 'gid': 1000, 'egid': 1000},
        'environment': {'HOME': HOME, 'ZDOTDIR': None},
        'files': fresh_tree() if files is None else files,
        'newuser': {'module': True, 'script_dirs': SCRIPT_DIRS} if newuser is None else newuser,
    })


def newuser_entries(result):
    return [e for e in result['sequence'] if e['phase'] == 'newuser']


def test_newuser_script_runs_after_global_zshenv_when_no_user_files_exist():
    # The #1372 review case: every user file and .zwc absent used to report complete with no newuser step.
    result = run_new()
    assert runs(result) == ['/etc/zsh/zshenv', VERSION_NEWUSER, '/etc/zsh/zshrc']
    assert [e['decision'] for e in newuser_entries(result)] == ['absent', 'reads']
    assert result['complete'] is True


@pytest.mark.parametrize('overrides', [
    {f'{HOME}/.zlogout': {'type': 'file', 'mtime': 1, 'readable': True}},  # .zlogout is not checked
    {f'{HOME}/.zshrc': {'type': 'absent'}},  # a dangling symlink follows to absent
])
def test_newuser_still_runs_with_only_zlogout_or_dangling_symlink(overrides):
    assert VERSION_NEWUSER in runs(run_new(files=fresh_tree(**overrides)))


@pytest.mark.parametrize('meta', [{'type': 'file', 'mtime': 1, 'readable': True},
                                  {'type': 'file', 'mtime': 1, 'readable': False},
                                  {'type': 'directory', 'mtime': 1}])
def test_any_existing_checked_user_file_suppresses_newuser(meta):
    result = run_new(files=fresh_tree(**{f'{HOME}/.zlogin': meta}), newuser={})
    assert [e['decision'] for e in newuser_entries(result)] == ['skipped_user_files_exist']
    assert VERSION_NEWUSER not in runs(result) and 'newuser_not_observed' not in codes(result)


def test_newuser_ignores_no_global_rcs_but_not_no_rcs_or_privileged():
    assert runs(run_new(options=['-i', '-d'])) == ['/etc/zsh/zshenv', VERSION_NEWUSER]
    assert [e['decision'] for e in newuser_entries(run_new(options=['-i', '-f']))] == ['skipped_no_rcs']
    assert [e['decision'] for e in newuser_entries(run_new(options=['-i', '-p']))] == ['skipped_privileged']
    privileged = run_new(ids={'uid': 1000, 'euid': 0, 'gid': 1000, 'egid': 1000})
    assert VERSION_NEWUSER not in runs(privileged)


def test_noninteractive_shell_has_no_newuser_step():
    result = run(files=fresh_tree())
    assert newuser_entries(result) == [] and result['complete'] is True


def test_site_script_wins_and_directory_stops_the_search():
    site = run_new(files=fresh_tree(**{SITE_NEWUSER: {'type': 'file', 'mtime': 1, 'readable': True}}))
    assert [e['decision'] for e in newuser_entries(site)] == ['reads', 'not_reached']
    assert SITE_NEWUSER in runs(site) and VERSION_NEWUSER not in runs(site)
    directory = run_new(files=fresh_tree(**{SITE_NEWUSER: {'type': 'directory', 'mtime': 1}}))
    assert [e['decision'] for e in newuser_entries(directory)] == ['skipped_directory', 'not_reached']
    unreadable = run_new(files=fresh_tree(**{SITE_NEWUSER: {'type': 'file', 'mtime': 1, 'readable': False}}))
    assert [e['decision'] for e in newuser_entries(unreadable)] == ['skipped_unreadable', 'reads']


def test_compiled_newuser_script_is_blocking():
    result = run_new(files=fresh_tree(**{VERSION_NEWUSER + '.zwc': {'type': 'file', 'mtime': 200}}))
    assert newuser_entries(result)[1]['decision'] == 'reads_compiled'
    assert 'compiled_file_unverified' in codes(result) and result['complete'] is False


def test_unavailable_module_runs_no_script():
    result = run_new(newuser={'module': False, 'script_dirs': SCRIPT_DIRS})
    assert [e['decision'] for e in newuser_entries(result)] == ['module_unavailable']
    assert result['complete'] is True


@pytest.mark.parametrize('newuser', [{}, {'module': True}, {'module': 'yes', 'script_dirs': []},
                                     {'module': True, 'script_dirs': ['relative']},
                                     {'module': True, 'script_dirs': ['/a', '/b', '/c']}])
def test_unobserved_newuser_build_is_blocking(newuser):
    result = run_new(newuser=newuser)
    assert 'newuser_not_observed' in codes(result) and result['complete'] is False


def test_unobserved_checked_user_file_leaves_newuser_unresolved():
    files = fresh_tree()
    del files[f'{HOME}/.zlogin']  # not in an interactive non-login sequence, but newuser checks it
    result = run_new(files=files)
    assert newuser_entries(result)[0]['decision'] == 'unresolved'
    assert 'file_not_observed' in codes(result) and result['complete'] is False


def test_unobserved_newuser_candidate_is_blocking():
    files = fresh_tree()
    del files[SITE_NEWUSER]
    result = run_new(files=files)
    assert [e['decision'] for e in newuser_entries(result)] == ['unresolved', 'unresolved']
    assert result['complete'] is False
