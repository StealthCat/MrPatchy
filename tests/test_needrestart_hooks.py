import copy
import shutil
import subprocess

import pytest

from app import needrestart_hooks as nr

SHIPPED = {
    'family': 'debian',
    'package': {'state': 'installed', 'version': '3.6-7ubuntu4.6'},
    'apt_conf': {'state': 'present', 'sha256': nr.SHIPPED_SHA256[nr.APT_CONF]},
    'apt_pinvoke': {'state': 'present', 'sha256': nr.SHIPPED_SHA256[nr.APT_PINVOKE]},
    'config': {'state': 'present', 'sha256': nr.SHIPPED_SHA256[nr.CONF]},
    'conf_d': {'state': 'listed', 'entries': [
        {'name': 'README.needrestart', 'kind': 'regular', 'executable': False},
    ]},
    'hook_d': {'state': 'listed', 'entries': [
        {'name': '90-none', 'kind': 'regular', 'executable': True},
        {'name': '10-dpkg', 'kind': 'regular', 'executable': True},
        {'name': '20-rpm', 'kind': 'regular', 'executable': True},
    ]},
    'notify_d': {'state': 'listed', 'entries': [
        {'name': '600-mail', 'kind': 'regular', 'executable': True},
        {'name': '200-write', 'kind': 'regular', 'executable': True},
        {'name': '400-notify-send', 'kind': 'regular', 'executable': True},
        {'name': 'README.needrestart', 'kind': 'regular', 'executable': False},
    ]},
    'restart_d': {'state': 'listed', 'entries': [
        {'name': 'dbus.service', 'kind': 'regular', 'executable': True},
        {'name': 'systemd-manager', 'kind': 'regular', 'executable': True},
        {'name': 'sysv-init', 'kind': 'regular', 'executable': True},
        {'name': 'README.needrestart', 'kind': 'regular', 'executable': False},
    ]},
}


def obs(**changes):
    value = copy.deepcopy(SHIPPED)
    value.update(changes)
    return value


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def runs(section):
    return [(p['name'], p['runs']) for p in section['programs']]


def test_shipped_ubuntu_layout_is_covered_and_ordered():
    result = nr.resolve(obs())
    assert result['covered'] and result['applicable'] and not result['gaps']
    assert result['origin'] == 'not_assessed' and result['runs_as'] == 'root'
    assert result['trigger']['apt_post_invoke'] is True
    assert result['perl_config'] == [{'path': nr.CONF, 'order': 1, 'evaluated': True, 'understood': True}]
    assert result['restart_mode_under_apt'] == 'automatic' and result['sendnotify'] is True
    assert [p['name'] for p in result['hook_d']['programs']] == ['10-dpkg', '20-rpm', '90-none']
    assert [p['order'] for p in result['hook_d']['programs']] == [1, 2, 3]
    assert runs(result['notify_d']) == [
        ('200-write', True), ('400-notify-send', True), ('600-mail', True), ('README.needrestart', False)]
    assert [p['order'] for p in result['notify_d']['programs']] == [1, 2, 3, None]
    restart = {p['name']: p for p in result['restart_d']['programs']}
    assert restart['dbus.service']['runs'] and restart['dbus.service']['replaces_restart_of'] == 'dbus.service'
    assert restart['README.needrestart']['runs'] is False


def test_conf_d_glob_skips_dot_and_non_conf_and_sorts_bytes():
    entries = [
        {'name': 'b.conf', 'kind': 'regular', 'text': "$nrconf{restart} = 'l';\n"},
        {'name': '.hidden.conf', 'kind': 'regular', 'text': 'system("id");'},
        {'name': 'Z.conf', 'kind': 'regular', 'text': '# comment only\n\n'},
        {'name': 'a.conf.bak', 'kind': 'regular', 'text': 'system("id");'},
        {'name': 'd.conf', 'kind': 'directory'},
        {'name': 'a.conf', 'kind': 'regular', 'text': "$nrconf{'sendnotify'} = 0; # quiet\n"},
    ]
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': entries}))
    assert result['covered'], result['gaps']
    assert [r['path'].rsplit('/', 1)[1] for r in result['perl_config']] == [
        'needrestart.conf', 'Z.conf', 'a.conf', 'b.conf', 'd.conf']
    assert result['perl_config'][-1]['evaluated'] is False
    assert result['restart_mode_under_apt'] == 'list_only' and result['sendnotify'] is False


def test_ui_setting_makes_apt_runs_interactive():
    entries = [{'name': 'ui.conf', 'kind': 'regular', 'text': '$nrconf{ui} = q(NeedRestart::UI::stdio);\n'}]
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': entries}))
    assert result['covered'] and result['restart_mode_under_apt'] == 'interactive'


@pytest.mark.parametrize('text,code', [
    ('system("curl x | sh");\n', 'config_unrecognized_code'),
    ('$nrconf{restart} = "$x";\n', 'config_unrecognized_code'),
    ("$nrconf{hook_d} = '/tmp/h';\n", 'directory_overridden'),
    ("$nrconf{notify_d} = '/tmp/n';\n", 'directory_overridden'),
])
def test_conf_d_code_that_cannot_be_understood_fails_closed(text, code):
    entries = [{'name': 'x.conf', 'kind': 'regular', 'text': text}]
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': entries}))
    assert code in codes(result) and not result['covered']
    assert result['perl_config'][1]['evaluated'] is True
    assert result['hook_d'] is None and result['restart_mode_under_apt'] is None


def test_unread_conf_d_file_and_modified_main_config_are_gaps():
    entries = [{'name': 'x.conf', 'kind': 'regular'}]
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': entries}))
    assert 'config_unread' in codes(result) and not result['covered']
    result = nr.resolve(obs(config={'state': 'present', 'sha256': '0' * 64}))
    assert 'config_modified' in codes(result) and result['hook_d'] is None
    assert result['perl_config'][0]['understood'] is False


def test_notify_d_skips_backup_dpkg_dot_and_non_executable_names():
    entries = [
        {'name': 'a~', 'kind': 'regular', 'executable': True},
        {'name': 'b.dpkg-old', 'kind': 'regular', 'executable': True},
        {'name': 'c.dpkg-x.y', 'kind': 'regular', 'executable': True},
        {'name': '.hidden', 'kind': 'regular', 'executable': True},
        {'name': 'd', 'kind': 'directory', 'executable': True},
        {'name': 'e', 'kind': 'regular', 'executable': False},
    ]
    result = nr.resolve(obs(notify_d={'state': 'listed', 'entries': entries}))
    section = {p['name']: p for p in result['notify_d']['programs']}
    assert '.hidden' not in section
    assert section['b.dpkg-old']['reason'] == 'skipped_backup_or_dpkg_name'
    assert section['c.dpkg-x.y']['runs'] is True
    assert section['d']['reason'] == 'directory_exec_fails' and section['d']['runs'] is False
    assert section['e']['reason'] == 'not_executable_skipped'
    assert result['covered'], result['gaps']  # skipped names do not affect the order


def test_hook_d_runs_without_execute_check_and_unresolved_order_is_a_gap():
    entries = [
        {'name': '5-x', 'kind': 'regular', 'executable': True},
        {'name': '10-y', 'kind': 'regular', 'executable': True},
        {'name': '00-off', 'kind': 'regular', 'executable': False},
    ]
    result = nr.resolve(obs(hook_d={'state': 'listed', 'entries': entries}))
    assert 'order_unresolved' in codes(result) and not result['covered']
    programs = {p['name']: p for p in result['hook_d']['programs']}
    assert programs['00-off']['reason'] == 'not_executable_exec_fails'
    assert programs['5-x']['order'] is None
    result = nr.resolve(obs(hook_d={'state': 'listed', 'entries': [
        {'name': 'Hook', 'kind': 'regular', 'executable': True}]}))
    assert 'order_unresolved' in codes(result)


def test_unknown_and_special_entries_are_gaps():
    result = nr.resolve(obs(hook_d={'state': 'listed', 'entries': [
        {'name': 'a', 'kind': 'regular'}, {'name': 'b', 'kind': 'other'}]}))
    assert {'entry_unknown', 'entry_special_file'} <= set(codes(result))
    result = nr.resolve(obs(notify_d={'state': 'unknown'}))
    assert 'directory_unknown' in codes(result)
    result = nr.resolve(obs(restart_d={'state': 'listed', 'complete': False, 'entries': []}))
    assert 'directory_incomplete' in codes(result)


def test_trigger_states():
    result = nr.resolve(obs(apt_conf={'state': 'absent'}))
    assert result['trigger']['apt_post_invoke'] is False and result['covered']
    result = nr.resolve(obs(apt_pinvoke={'state': 'present', 'sha256': '1' * 64}))
    assert 'trigger_modified' in codes(result)
    result = nr.resolve(obs(apt_conf={'state': 'unknown'}))
    assert 'trigger_unknown' in codes(result)


def test_aborting_configurations_run_no_hooks():
    result = nr.resolve(obs(config={'state': 'absent'}))
    assert result['trigger']['needrestart_aborts'] == 'config_missing' and result['hook_d'] is None
    assert result['covered']
    result = nr.resolve(obs(hook_d={'state': 'absent'}))
    assert result['trigger']['needrestart_aborts'] == 'hook_directory_missing'
    assert result['notify_d'] is None and result['covered']
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': [
        {'name': 'r.conf', 'kind': 'regular', 'text': "$nrconf{restart} = 'z';\n"}]}))
    assert 'restart_mode_invalid' in codes(result)


def test_applicability_and_support():
    result = nr.resolve(obs(package={'state': 'absent'}))
    assert result['covered'] and not result['applicable']
    for package in ({'state': 'installed', 'version': '3.6-4+deb12u1'}, {'state': 'installed', 'version': None}):
        result = nr.resolve(obs(package=package))
        assert codes(result) == ['unsupported_version'] and not result['covered']
    assert codes(nr.resolve(obs(package={'state': 'unknown'}))) == ['package_unknown']
    assert codes(nr.resolve(obs(family='rpm'))) == ['unsupported_family']


@pytest.mark.parametrize('bad', [
    None,
    {'family': 'debian'},
    obs(family='windows'),
    obs(config={'state': 'maybe'}),
    obs(config={'state': 'present', 'sha256': 'XYZ'}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': 'a/b', 'kind': 'regular', 'executable': True}]}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': 'a', 'kind': 'regular', 'executable': True}] * 2}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': 'a', 'kind': 'socket'}]}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': 'a', 'kind': 'regular', 'executable': 'yes'}]}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': '..', 'kind': 'regular', 'executable': True}]}),
    obs(hook_d={'state': 'listed', 'entries': [{'name': str(i), 'kind': 'regular', 'executable': True}
                                               for i in range(nr.MAX_ENTRIES + 1)]}),
])
def test_malformed_observations_are_rejected(bad):
    with pytest.raises(nr.Invalid):
        nr.resolve(bad)


PERL = shutil.which('perl')


@pytest.mark.skipif(PERL is None, reason='perl is not installed')
def test_conf_d_glob_sort_and_notify_skip_match_perl(tmp_path):
    names = ['b.conf', '.h.conf', 'Z.conf', 'a.conf.bak', 'a.conf', '10.conf', '9.conf', '_x.conf', 'x.CONF']
    conf_d = tmp_path / 'conf.d'
    conf_d.mkdir()
    for name in names:
        (conf_d / name).write_text("$nrconf{verbosity} = 1;\n")
    # The exact loop expression from the shipped needrestart.conf.
    perl = subprocess.run([PERL, '-e', 'print "$_\\n" for sort <$ARGV[0]/*.conf>', str(conf_d)],
                          check=True, capture_output=True, text=True).stdout.split()
    entries = [{'name': n, 'kind': 'regular', 'text': "$nrconf{verbosity} = 1;\n"} for n in names]
    result = nr.resolve(obs(conf_d={'state': 'listed', 'entries': entries}))
    ours = [r['path'].rsplit('/', 1)[1] for r in result['perl_config'][1:]]
    assert ours == [p.rsplit('/', 1)[1] for p in perl]

    candidates = ['a~', 'b.dpkg-old', 'c.dpkg-x.y', 'd.dpkg-', 'e.dpkg-new~', 'f.dpkg-dist', 'g']
    script = 'for (@ARGV) { print "$_\\n" unless /(~|\\.dpkg-[^.]+)$/ }'
    kept = subprocess.run([PERL, '-e', script, *[f'{nr.NOTIFY_D}/{c}' for c in candidates]],
                          check=True, capture_output=True, text=True).stdout.split()
    entries = [{'name': c, 'kind': 'regular', 'executable': True} for c in candidates]
    result = nr.resolve(obs(notify_d={'state': 'listed', 'entries': entries}))
    assert sorted(p['path'] for p in result['notify_d']['programs'] if p['runs']) == sorted(kept)
