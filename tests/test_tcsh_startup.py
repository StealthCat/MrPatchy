"""Tests for the pure tcsh/csh startup-file contract (#1463).

Expected orders come from Ubuntu 24.04 tcsh 6.24.10 runs recorded in the PR.
"""
from __future__ import annotations

import pytest

from app import tcsh_startup as ts

HOME = '/home/alice'
SYSTEM = ('/etc/csh.cshrc', '/etc/csh.login', '/etc/csh.logout')
USER = ('.tcshrc', '.cshrc', '.login', '.cshdirs', '.logout')
BUILD = ['wide', 'nls', 'dl', 'al', 'kan', 'sm', 'rh', 'nd', 'color', 'filec']


def tree(home=HOME, **overrides):
    files = {path: {'type': 'file', 'readable': True} for path in SYSTEM}
    for name in USER:
        files[f'{home.rstrip("/")}/{name}'] = {'type': 'file', 'readable': True}
    files.update(overrides)
    return files


def run(argv0='tcsh', arguments=('-c', 'true'), home=HOME, files=None, build=None, family='debian',
        environment=None):
    return ts.evaluate({
        'family': family,
        'build_options': BUILD if build is None else build,
        'invocation': {'argv0': argv0, 'arguments': list(arguments)},
        'environment': {'HOME': home} if environment is None else environment,
        'files': tree(home if home else '/') if files is None else files,
    })


def runs(result, phase=None):
    return [r['path'] for r in result['runs'] if phase is None or r['phase'] == phase]


def codes(result):
    return {g['code'] for g in result['gaps']}


def decision(result, path):
    return next(e['decision'] for e in result['sequence'] if e['path'] == path)


def test_noninteractive_command_reads_cshrc_and_tcshrc():
    result = run()
    assert result['session'] == 'nonlogin' and result['complete'] is True
    assert runs(result) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc']
    assert decision(result, f'{HOME}/.cshrc') == 'fallback_not_used'
    assert decision(result, f'{HOME}/.login') == 'not_in_session'


def test_script_operand_reads_the_same_files():
    assert runs(run(arguments=['/tmp/s.csh'])) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc']


@pytest.mark.parametrize('argv0,arguments', [('-tcsh', []), ('tcsh', ['-l']), ('-csh', ['-c', 'true']),
                                             ('-tcsh', ['/tmp/s.csh'])])
def test_login_order_and_logout(argv0, arguments):
    result = run(argv0=argv0, arguments=arguments)
    assert result['session'] == 'login' and result['complete'] is True
    assert runs(result, 'startup') == ['/etc/csh.cshrc', '/etc/csh.login', f'{HOME}/.tcshrc', f'{HOME}/.login',
                                       f'{HOME}/.cshdirs']
    assert runs(result, 'logout') == ['/etc/csh.logout', f'{HOME}/.logout']


def test_dash_d_reads_cshdirs_in_a_nonlogin_shell():
    assert runs(run(arguments=['-d', '-c', 'true'])) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc', f'{HOME}/.cshdirs']


@pytest.mark.parametrize('arguments', [['-l', '-c', 'true'], ['-fl'], ['-ql']])
def test_dash_l_with_other_arguments_is_rejected(arguments):
    result = run(arguments=arguments)
    assert result['runs'] == [] and result['complete'] is True
    assert {e['decision'] for e in result['sequence']} == {'not_started'}


def test_options_continue_after_the_command_word():
    rejected = run(arguments=['-c', 'true', '-l'])
    assert rejected['runs'] == [] and decision(rejected, '/etc/csh.cshrc') == 'not_started'
    assert run(arguments=['-c', 'true', '-f'])['runs'] == []
    # The word after -c is the command even when it starts with -, and a plain word ends parsing.
    assert runs(run(arguments=['-c', '-f'])) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc']
    assert runs(run(arguments=['-c', 'true', 'a', '-l'])) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc']


def test_dash_c_without_a_command_is_blocking():
    assert 'options_unverified' in codes(run(arguments=['-c']))


@pytest.mark.parametrize('arguments', [['-f', '-c', 'true'], ['-fc', 'true'], ['-d', '-f', '-c', 'true']])
def test_fast_skips_every_startup_file_but_not_logout(arguments):
    result = run(argv0='-tcsh', arguments=arguments)
    assert runs(result, 'startup') == [] and result['complete'] is True
    assert decision(result, '/etc/csh.cshrc') == 'skipped_fast'
    assert runs(result, 'logout') == ['/etc/csh.logout', f'{HOME}/.logout']


def test_unset_home_skips_startup_files_and_user_logout():
    result = run(argv0='-tcsh', home=None, files={'/etc/csh.logout': {'type': 'file', 'readable': True}})
    assert runs(result) == ['/etc/csh.logout'] and result['complete'] is True
    assert decision(result, '/etc/csh.cshrc') == 'skipped_no_home'
    assert decision(result, '$HOME/.logout') == 'skipped_no_home'
    assert result['home'] is None


def test_empty_home_resolves_user_files_under_root():
    result = run(home='', files=tree('/'))
    assert runs(result) == ['/etc/csh.cshrc', '/.tcshrc'] and result['complete'] is True


def test_trailing_slash_home_is_normalised():
    assert runs(run(home=HOME + '/')) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc']


def test_relative_home_is_a_blocking_gap():
    result = run(home='alice', files={})
    assert 'home_relative' in codes(result) and result['complete'] is False
    assert result['runs'] == []


def test_unobserved_home_is_a_blocking_gap():
    result = run(environment={})
    assert 'home_not_observed' in codes(result) and result['complete'] is False
    assert decision(result, '/etc/csh.cshrc') == 'unresolved'


@pytest.mark.parametrize('kind', [{'type': 'absent'}, {'type': 'file', 'readable': False}])
def test_cshrc_fallback_when_tcshrc_cannot_be_opened(kind):
    result = run(files=tree(**{f'{HOME}/.tcshrc': kind}))
    assert runs(result) == ['/etc/csh.cshrc', f'{HOME}/.cshrc'] and result['complete'] is True


def test_directory_tcshrc_blocks_the_fallback_but_not_later_files():
    result = run(argv0='-tcsh', arguments=[], files=tree(**{f'{HOME}/.tcshrc': {'type': 'directory'}}))
    assert runs(result, 'startup') == ['/etc/csh.cshrc', '/etc/csh.login', f'{HOME}/.login', f'{HOME}/.cshdirs']
    assert result['complete'] is True
    assert decision(result, f'{HOME}/.tcshrc') == 'opened_directory'
    assert decision(result, f'{HOME}/.cshrc') == 'fallback_not_used'


def test_unreadable_or_directory_files_are_skipped_silently():
    files = tree(**{'/etc/csh.cshrc': {'type': 'directory'}, f'{HOME}/.login': {'type': 'file', 'readable': False},
                    f'{HOME}/.cshdirs': {'type': 'directory'}, '/etc/csh.login': {'type': 'absent'},
                    '/etc/csh.logout': {'type': 'directory'}})
    result = run(argv0='-tcsh', arguments=[], files=files)
    assert runs(result) == [f'{HOME}/.tcshrc', f'{HOME}/.logout'] and result['complete'] is True
    assert decision(result, f'{HOME}/.login') == 'skipped_unreadable'
    assert decision(result, '/etc/csh.cshrc') == 'skipped_directory'


def test_special_file_is_blocking_and_leaves_the_fallback_unresolved():
    result = run(files=tree(**{f'{HOME}/.tcshrc': {'type': 'other'}}))
    assert 'special_file' in codes(result) and result['complete'] is False
    assert decision(result, f'{HOME}/.cshrc') == 'unresolved'


def test_unobserved_file_is_blocking():
    files = tree()
    del files[f'{HOME}/.tcshrc']
    result = run(files=files)
    assert 'file_not_observed' in codes(result) and result['complete'] is False
    assert decision(result, f'{HOME}/.cshrc') == 'unresolved'


def test_cshrc_is_not_required_when_tcshrc_opens():
    files = tree()
    del files[f'{HOME}/.cshrc']
    assert run(files=files)['complete'] is True


@pytest.mark.parametrize('arguments', [['-n', '-c', 'true'], ['-b', 'x'], ['--', '-c', 'true'],
                                       ['-DHOME=/x', '-c', 'true']])
def test_unmodelled_options_are_blocking(arguments):
    result = run(arguments=arguments)
    assert 'options_unverified' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('arguments', [['-m', '-c', 'true'], ['-qeV', '-c', 'true'], ['-ivxXtsF'], ['-']])
def test_neutral_options_do_not_change_the_files(arguments):
    result = run(arguments=arguments)
    assert runs(result) == ['/etc/csh.cshrc', f'{HOME}/.tcshrc'] and result['complete'] is True


def test_login_first_build_is_not_modelled():
    result = run(build=BUILD + ['lf'])
    assert 'build_order_unsupported' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('build', [None, 'wide', [1]])
def test_unobserved_build_is_blocking(build):
    result = ts.evaluate({'family': 'debian', 'build_options': build,
                          'invocation': {'argv0': 'tcsh', 'arguments': []},
                          'environment': {'HOME': HOME}, 'files': tree()})
    assert 'build_not_observed' in codes(result) and result['complete'] is False


@pytest.mark.parametrize('family,code', [(None, 'family_not_observed'), ('rpm', 'family_unsupported')])
def test_family_gaps(family, code):
    result = run(family=family)
    assert code in codes(result) and result['sequence'] == [] and result['complete'] is False


@pytest.mark.parametrize('payload', [None, [], {'invocation': 'x'}, {'invocation': {'argv0': ''}},
                                     {'invocation': {'argv0': 'tcsh', 'arguments': ['a\nb']}},
                                     {'invocation': {'argv0': 'tcsh', 'arguments': ['-c'] * 65}}])
def test_malformed_input_is_never_complete(payload):
    result = ts.evaluate(payload)
    assert result['complete'] is False and result['runs'] == []


def test_overlong_home_is_malformed():
    result = run(home='/' + 'a' * ts.PATH_MAX, files={})
    assert 'input_malformed' in codes(result) and result['complete'] is False


def test_gap_list_is_bounded():
    gaps: list = []
    for i in range(ts.MAX_GAPS + 5):
        ts._gap(gaps, 'file_not_observed', f'/p{i}')
    assert len(gaps) == ts.MAX_GAPS and gaps[-1]['code'] == 'gaps_truncated'


def test_result_is_metadata_only():
    result = run()
    assert result['note'].startswith('File metadata only') and result['unobserved']
    assert set(result) >= {'contract_version', 'reference', 'sequence', 'runs', 'gaps', 'complete'}
