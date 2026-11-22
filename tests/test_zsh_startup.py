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
