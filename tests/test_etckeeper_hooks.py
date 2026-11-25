import copy
import os
import shutil
import subprocess

import pytest

from app import etckeeper_hooks as ek


def _listing(command):
    return {'state': 'listed', 'entries': [
        {'name': name, 'kind': 'regular', 'executable': True, 'sha256': digest}
        for name, digest in ek.SHIPPED_SCRIPTS[command].items()
    ] + [{'name': 'README', 'kind': 'regular', 'executable': False, 'sha256': None}]}


def _file(path, **extra):
    return {'state': 'present', 'sha256': ek.SHIPPED_FILES[path], **extra}


SHIPPED = {
    'package': {'state': 'installed', 'version': ek.SUPPORTED_VERSION},
    'program': _file(ek.PROGRAM, executable=True),
    'conf': _file(ek.CONF),
    'apt_conf': _file(ek.APT_CONF),
    'cron_daily': _file(ek.CRON_DAILY),
    'daily': _file(ek.DAILY),
    'service': _file(ek.SERVICE),
    'timer': _file(ek.TIMER),
    'timer_enabled': 'enabled',
    'perl': 'present',
    'repositories': {'git': 'present'},
    'directories': {command: _listing(command) for command in ek.COMMANDS},
}


def obs(**changes):
    value = copy.deepcopy(SHIPPED)
    value.update(changes)
    return value


def with_dir(command, entries, **extra):
    value = obs()
    value['directories'][command] = {'state': 'listed', 'entries': entries, **extra}
    return value


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def trigger(result, trigger_id):
    return next(item for item in result['triggers'] if item['id'] == trigger_id)


def command(result, name):
    return next(item for item in result['commands'] if item['command'] == name)


def test_shipped_install_resolves_apt_and_daily_triggers_except_vcs_hooks():
    result = ek.evaluate(obs())
    assert result['authorizes_response'] is False
    assert result['stops_on_failure'] is True
    assert result['conf']['understood'] is True
    # Only the VCS-running shipped commit scripts leave a gap.
    assert set(codes(result)) == {'vcs_hooks_not_resolved'}
    assert result['covered'] is False
    pre = trigger(result, 'apt_pre_invoke')
    assert pre['state'] == 'active' and pre['runs_as'] == 'root'
    paths = [step['path'] for step in pre['steps']]
    assert paths[:2] == ['/etc/etckeeper/pre-install.d/10packagelist',
                         '/etc/etckeeper/list-installed.d/50list-installed']
    # 50uncommitted-changes runs unclean and then commit.
    assert paths.index('/etc/etckeeper/unclean.d/50test') < paths.index('/etc/etckeeper/commit.d/10vcs-test')
    assert paths[-1] == '/etc/etckeeper/commit.d/99push'
    post = trigger(result, 'apt_post_invoke')
    assert [step['command'] for step in post['steps']][:3] == ['post-install', 'unclean', 'list-installed']
    assert trigger(result, 'cron_daily')['state'] == 'active'
    assert trigger(result, 'systemd_timer')['state'] == 'active'
    assert all(script['provenance'] == 'shipped_unchanged'
               for item in result['commands'] for script in item['scripts'])


def test_without_vcs_runners_shipped_install_is_covered():
    value = obs()
    value['directories']['commit'] = _listing('commit')
    value['directories']['commit']['entries'] = [
        entry for entry in value['directories']['commit']['entries']
        if entry['name'] not in ('50vcs-commit', '99push')]
    assert ek.evaluate(value)['covered'] is True


def test_selection_skips_dot_names_bad_names_directories_and_non_executables():
    result = ek.evaluate(with_dir('unclean', [
        {'name': '.hidden', 'kind': 'regular', 'executable': True, 'sha256': None},
        {'name': 'run.sh', 'kind': 'regular', 'executable': True, 'sha256': None},
        {'name': '50test.dpkg-old', 'kind': 'regular', 'executable': True, 'sha256': None},
        {'name': 'sub', 'kind': 'directory', 'executable': True, 'sha256': None},
        {'name': 'off', 'kind': 'regular', 'executable': False, 'sha256': None},
        {'name': '50test', 'kind': 'regular', 'executable': True,
         'sha256': ek.SHIPPED_SCRIPTS['unclean']['50test']},
    ]))
    unclean = command(result, 'unclean')
    assert [script['name'] for script in unclean['scripts']] == ['50test']
    assert {item['name']: item['reason'] for item in unclean['skipped']} == {
        '.hidden': 'dot_name_not_globbed', 'run.sh': 'name_not_selected',
        '50test.dpkg-old': 'name_not_selected', 'sub': 'directory', 'off': 'not_executable'}


def test_custom_and_modified_scripts_run_but_their_invocations_are_unresolved():
    result = ek.evaluate(with_dir('pre-install', [
        {'name': '10packagelist', 'kind': 'regular', 'executable': True, 'sha256': 'a' * 64},
        {'name': '05backdoor', 'kind': 'other', 'executable': True, 'sha256': 'b' * 64},
        {'name': '99nohash', 'kind': 'regular', 'executable': True, 'sha256': None},
    ]))
    scripts = command(result, 'pre-install')['scripts']
    assert [(s['name'], s['provenance']) for s in scripts] == [
        ('05backdoor', 'custom'), ('10packagelist', 'shipped_modified'), ('99nohash', 'unverified')]
    assert all(s['invocations_resolved'] is False and s['runs_as'] == 'root' for s in scripts)
    assert codes(result).count('invocations_unresolved') == 3
    # A modified shipped script is not followed into list-installed.
    steps = trigger(result, 'apt_pre_invoke')['steps']
    assert [step['command'] for step in steps] == ['pre-install'] * 3
    assert result['covered'] is False


ORDER_NAMES = ['b', 'A', 'a', 'B', '10x', '9x', 'Z-1', '50Vcs', '50vcs-commit']


def _entries(names):
    return [{'name': name, 'kind': 'regular', 'executable': True, 'sha256': 'c' * 64} for name in names]


def test_perl_order_is_case_folded_then_bytes_and_fallback_is_bytes():
    perl = command(ek.evaluate(with_dir('unclean', _entries(ORDER_NAMES))), 'unclean')
    assert [s['name'] for s in perl['scripts']] == ['10x', '50Vcs', '50vcs-commit', '9x', 'A', 'a', 'B', 'b', 'Z-1']
    shell = command(ek.evaluate({**with_dir('unclean', _entries(ORDER_NAMES)), 'perl': 'absent'}), 'unclean')
    assert [s['name'] for s in shell['scripts']] == ['10x', '50Vcs', '50vcs-commit', '9x', 'A', 'B', 'Z-1', 'a', 'b']
    unknown = ek.evaluate({**with_dir('unclean', _entries(ORDER_NAMES)), 'perl': 'unknown'})
    assert command(unknown, 'unclean')['order_resolved'] is False
    assert 'order_unresolved' in codes(unknown)
    # Lower-case names order the same either way, so unknown Perl is not a gap.
    same = ek.evaluate({**with_dir('unclean', _entries(['20b', '10a'])), 'perl': 'unknown'})
    assert command(same, 'unclean')['order_resolved'] is True


@pytest.mark.skipif(shutil.which('perl') is None, reason='perl is not installed')
def test_order_and_selection_match_the_real_lsscripts(tmp_path):
    names = ORDER_NAMES + ['.dot', 'x.sh', 'off']
    for name in names:
        path = tmp_path / name
        path.write_text('#!/bin/sh\n')
        path.chmod(0o644 if name == 'off' else 0o755)
    (tmp_path / 'sub').mkdir()
    # The lsscripts body from /usr/bin/etckeeper 1.18.20.
    script = ('$dir=shift; print join "\\n", grep { ! -d $_ && -x $_ } '
              'grep /^\\Q$dir\\/\\E[-a-zA-Z0-9]+$/, glob "$dir/*";')
    output = subprocess.run(['perl', '-e', script, str(tmp_path)], capture_output=True, text=True, check=True,
                            env={**os.environ, 'LANG': 'C'}).stdout
    expected = [line.rsplit('/', 1)[1] for line in output.splitlines()]
    entries = [{'name': name, 'kind': 'regular', 'executable': name != 'off', 'sha256': None} for name in names]
    entries.append({'name': 'sub', 'kind': 'directory', 'executable': True, 'sha256': None})
    result = ek.evaluate(with_dir('unclean', entries))
    assert [s['name'] for s in command(result, 'unclean')['scripts']] == expected


def test_trailing_newline_name_and_unknown_entries_are_gaps():
    result = ek.evaluate(with_dir('commit', [
        {'name': 'evil\n', 'kind': 'regular', 'executable': True, 'sha256': None},
        {'name': 'maybe', 'kind': 'unknown', 'executable': True, 'sha256': None},
        {'name': 'perm', 'kind': 'regular', 'executable': None, 'sha256': None},
    ]))
    assert codes(result).count('entry_unresolved') == 2
    assert 'name_unresolved' in codes(result)
    assert command(result, 'commit')['complete'] is False


def test_unknown_or_incomplete_directories_are_gaps():
    value = obs()
    del value['directories']['post-install']
    value['directories']['unclean']['complete'] = False
    result = ek.evaluate(value)
    assert {'directory_unknown', 'directory_incomplete'} <= set(codes(result))
    assert command(result, 'post-install')['state'] == 'unknown'


def test_missing_directory_means_the_command_runs_nothing():
    value = obs()
    value['directories']['pre-install'] = {'state': 'absent'}
    result = ek.evaluate(value)
    pre = command(result, 'pre-install')
    assert pre['scripts'] == [] and pre['complete'] is True and 'exits 1' in pre['note']
    assert trigger(result, 'apt_pre_invoke')['steps'] == []


def test_simple_conf_is_understood_and_avoid_daily_only_stops_cron():
    conf = '# local\nVCS="git"\nAVOID_DAILY_AUTOCOMMITS=1\nPUSH_REMOTE=""\n'
    result = ek.evaluate(obs(conf={'state': 'present', 'sha256': 'd' * 64, 'text': conf}))
    assert result['conf']['understood'] is True and result['conf']['provenance'] == 'modified'
    assert trigger(result, 'cron_daily')['state'] == 'inactive'
    timer = trigger(result, 'systemd_timer')
    assert timer['state'] == 'active' and timer['honours_avoid_daily_autocommits'] is False
    assert 'even with AVOID_DAILY_AUTOCOMMITS' in timer['note']


@pytest.mark.parametrize('text', [
    'VCS=git\n. /tmp/extra\n',
    'VCS="$(id)"\n',
    'VCS=`id`\n',
    'export VCS=git\n',
    'if true; then VCS=git; fi\n',
])
def test_conf_with_other_shell_is_not_understood(text):
    result = ek.evaluate(obs(conf={'state': 'present', 'sha256': 'e' * 64, 'text': text}))
    assert result['conf']['understood'] is False
    assert {'conf_not_understood', 'hook_directory_unresolved'} <= set(codes(result))
    assert trigger(result, 'cron_daily')['state'] == 'unknown'


def test_conf_redirecting_the_hook_directory_is_a_gap():
    text = 'VCS="git"\nETCKEEPER_CONF_DIR=/tmp/hooks\n'
    result = ek.evaluate(obs(conf={'state': 'present', 'sha256': 'f' * 64, 'text': text}))
    assert {'conf_redirects_directory', 'hook_directory_unresolved'} <= set(codes(result))


def test_modified_apt_hook_or_program_is_never_covered():
    result = ek.evaluate(obs(apt_conf={'state': 'present', 'sha256': '1' * 64},
                             program={'state': 'present', 'sha256': '2' * 64, 'executable': True}))
    assert {'apt_hook_not_verified', 'program_not_verified'} <= set(codes(result))
    assert trigger(result, 'apt_pre_invoke')['state'] == 'unknown'


def test_absent_apt_hook_and_non_executable_program_disable_triggers():
    result = ek.evaluate(obs(apt_conf={'state': 'absent'}))
    assert trigger(result, 'apt_pre_invoke')['state'] == 'inactive'
    off = ek.evaluate(obs(program={'state': 'present', 'sha256': ek.SHIPPED_FILES[ek.PROGRAM],
                                   'executable': False}))
    assert {t['state'] for t in off['triggers']} == {'inactive'}


def test_timer_enablement_unknown_and_disabled():
    unknown = ek.evaluate(obs(timer_enabled=None))
    assert trigger(unknown, 'systemd_timer')['state'] == 'unknown'
    assert 'timer_enablement_unknown' in codes(unknown)
    disabled = ek.evaluate(obs(timer_enabled='disabled'))
    assert trigger(disabled, 'systemd_timer')['state'] == 'inactive'


def test_no_vcs_means_no_hook_runs_and_unknown_vcs_is_a_gap():
    text = 'VCS=""\n'
    none = ek.evaluate(obs(conf={'state': 'present', 'sha256': '3' * 64, 'text': text},
                           repositories={name: 'absent' for name in ek.VCS_NAMES}))
    assert none['vcs'] == 'unset'
    assert {t['state'] for t in none['triggers']} == {'inactive'}
    unknown = ek.evaluate(obs(conf={'state': 'present', 'sha256': '3' * 64, 'text': text}, repositories={}))
    assert unknown['vcs'] == 'unknown' and 'vcs_unknown' in codes(unknown)


def test_unknown_conf_and_daily_leave_daily_triggers_unknown():
    result = ek.evaluate(obs(conf={'state': 'unknown'}, daily={'state': 'unknown'}))
    assert {'conf_unknown', 'daily_unknown'} <= set(codes(result))
    assert trigger(result, 'cron_daily')['state'] == 'unknown'
    assert trigger(result, 'systemd_timer')['state'] == 'unknown'


def test_not_installed_is_covered_and_version_drift_is_a_gap():
    absent = ek.evaluate({'package': {'state': 'absent'}, 'program': {'state': 'absent'}})
    assert absent == {**absent, 'installed': False, 'covered': True, 'triggers': [], 'gaps': []}
    drift = ek.evaluate(obs(package={'state': 'installed', 'version': '1.18.21-1'}))
    assert 'version_unsupported' in codes(drift)
    leftover = ek.evaluate(obs(package={'state': 'absent'}))
    assert 'program_without_package' in codes(leftover)


def test_gap_list_is_capped():
    entries = [{'name': f'x{i}', 'kind': 'unknown', 'executable': True, 'sha256': None} for i in range(400)]
    result = ek.evaluate(with_dir('commit', entries))
    assert len(result['gaps']) == ek.MAX_GAPS
    assert result['gaps'][-1]['code'] == 'gaps_truncated'


@pytest.mark.parametrize('bad', [
    None,
    {'package': {'state': 'maybe'}},
    {**SHIPPED, 'perl': 'yes'},
    {**SHIPPED, 'directories': {'not-a-command': {'state': 'absent'}}},
    {**SHIPPED, 'repositories': {'svn': 'present'}},
    {**SHIPPED, 'conf': {'state': 'present', 'sha256': 'XYZ'}},
    {**SHIPPED, 'directories': {'commit': {'state': 'listed', 'entries': [{'name': 'a/b'}]}}},
    {**SHIPPED, 'directories': {'commit': {'state': 'listed', 'entries': [{'name': 'a'}, {'name': 'a'}]}}},
    {**SHIPPED, 'directories': {'commit': {'state': 'listed', 'entries': [{'name': 'a', 'executable': 'y'}]}}},
])
def test_malformed_observations_are_rejected(bad):
    with pytest.raises(ek.Invalid):
        ek.evaluate(bad)
