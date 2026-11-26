"""Pure sudo.conf plugin and path contract (#1425)."""
import pytest

from app import sudo_conf_plugins as sc

SECURE = {'type': 'file', 'uid': 0, 'mode': 0o644}
PDIR = '/usr/libexec/sudo/'


def run(text, stat=SECURE):
    return sc.evaluate(exists=True, text=text, stat=stat)


def rows(result):
    return [(p['source'], p['symbol'], p['resolved_path'], p['type'], p['outcome']) for p in result['plugins']]


def test_comment_only_file_loads_the_default_sudoers_plugins():
    r = run('# Plugin sudoers_policy /tmp/x.so\n\n')
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed'
    assert rows(r) == [('default', 'sudoers_policy', PDIR + 'sudoers.so', 'policy', 'loaded'),
                       ('default', 'sudoers_audit', PDIR + 'sudoers.so', 'audit', 'loaded_if_present'),
                       ('default', 'sudoers_io', PDIR + 'sudoers.so', 'io', 'loaded')]
    assert all(p['runs_as'] == 'root' and p['code_runs'] for p in r['plugins'])
    assert r['paths']['noexec']['value'] == PDIR + 'sudo_noexec.so' and r['paths']['askpass']['value'] is None


def test_missing_file_uses_defaults_and_unchecked_file_fails_closed():
    absent = sc.evaluate(exists=False)
    assert absent['status'] == 'absent' and absent['complete'] and len(absent['plugins']) == 3
    for r in (sc.evaluate(exists=None), sc.evaluate(exists=True, text=None, stat=SECURE),
              sc.evaluate(exists=True, text='Plugin a b\n')):
        assert r['status'] == 'not_observed' and not r['complete'] and r['plugins'] == []
    assert sc.evaluate(exists=True, text='x\n')['gaps'][0]['code'] == 'file_security_not_observed'


def test_insecure_file_is_ignored_like_sudo_secure_fd():
    text = 'Path plugin_dir /tmp/evil/\n'
    for stat, reason in (({'type': 'file', 'uid': 0, 'mode': 0o664}, 'group_writable'),
                         ({'type': 'file', 'uid': 0, 'mode': 0o646}, 'world_writable'),
                         ({'type': 'file', 'uid': 1000, 'mode': 0o644}, 'not_owned_by_root'),
                         ({'type': 'directory', 'uid': 0, 'mode': 0o755}, 'not_regular_file')):
        r = run(text, stat)
        assert r['status'] == 'ignored_insecure' and r['ignored_reason'] == reason and r['complete']
        assert r['paths']['plugin_dir']['value'] == PDIR and r['plugins'][0]['resolved_path'] == PDIR + 'sudoers.so'



@pytest.mark.parametrize('stat', [
    {},
    {'uid': 0, 'mode': 0o644},
    {'type': 'file', 'mode': 0o644},
    {'type': 'file', 'uid': 0},
    {'type': None, 'uid': 0, 'mode': 0o644},
    {'type': 'file', 'uid': None, 'mode': 0o644},
    {'type': 'file', 'uid': 0, 'mode': None},
    {'type': 'file', 'uid': 0, 'mode': '0664'},
    {'type': 'file', 'uid': '0', 'mode': 0o644},
    {'type': 'file', 'uid': False, 'mode': 0o644},
    {'type': 'file', 'uid': 0, 'mode': True},
    {'type': '', 'uid': 0, 'mode': 0o644},
])
def test_partly_observed_stat_fails_closed_instead_of_hiding_plugins(stat):
    """Review of 8f322530: a dropped or malformed stat field must not read as insecure/secure."""
    r = run('Plugin sudoers_policy /tmp/evil.so\n', stat)
    assert r['status'] == 'not_observed' and not r['complete'] and r['plugins'] == []
    assert r['ignored_reason'] is None
    assert [g['code'] for g in r['gaps'] if g['blocking']] == ['file_security_not_observed']

def test_plugin_dir_override_moves_the_default_sudoers_object():
    # Verified on sudo 1.9.15p5: the constructor of /tmp/evil/sudoers.so ran as euid 0.
    r = run('Path plugin_dir /tmp/evil/\n')
    assert [p['resolved_path'] for p in r['plugins']] == ['/tmp/evil/sudoers.so'] * 3
    assert not r['complete'] and {g['code'] for g in r['gaps']} == {'plugin_type_unresolved'}
    assert r['paths']['plugin_dir'] == {**r['paths']['plugin_dir'], 'value': '/tmp/evil/', 'source': sc.CONF_PATH,
                                        'line': 1}


def test_relative_plugin_path_is_appended_without_a_separator():
    r = run('PATH PLUGIN_DIR /tmp/evil\nplugin sudoers_policy x.so opt=1 two\n')
    first = r['plugins'][0]
    assert first['resolved_path'] == '/tmp/evilx.so' and first['options'] == ['opt=1', 'two']
    assert first['type'] is None and first['outcome'] == 'loaded_type_unresolved' and not r['complete']
    assert r['plugins'][1]['outcome'] == 'loaded_if_no_policy_above'


def test_unset_plugin_dir_is_fatal_for_relative_plugins():
    r = run('Path plugin_dir\nPlugin sudoers_policy sudoers.so\n')
    assert r['status'] == 'fails' and r['fatal'] == 'plugin_dir_unset'
    assert r['plugins'][0]['outcome'] == 'fatal' and not r['plugins'][0]['code_runs']
    assert run('Path plugin_dir\n')['fatal'] == 'plugin_dir_unset'


def test_explicit_sudoers_policy_adds_audit_and_moves_options():
    r = run('Plugin sudoers_policy sudoers.so sudoers_file=/etc/sudoers.alt\n')
    assert rows(r) == [(sc.CONF_PATH, 'sudoers_policy', PDIR + 'sudoers.so', 'policy', 'loaded'),
                       ('default', 'sudoers_audit', PDIR + 'sudoers.so', 'audit', 'loaded_if_present')]
    assert r['plugins'][0]['options'] == [] and r['plugins'][1]['options'] == ['sudoers_file=/etc/sudoers.alt']
    assert r['plugins'][1]['options_moved_from_line'] == 1 and r['complete']


def test_second_policy_plugin_is_fatal_and_duplicates_are_ignored():
    r = run('Plugin sudoers_policy sudoers.so\nPlugin python_policy python_plugin.so ModulePath=/x.py\n')
    assert r['status'] == 'fails' and r['fatal'] == 'second_policy_plugin'
    assert r['plugins'][-1]['code_runs']
    r = run('Plugin sudoers_policy sudoers.so\nPlugin sudoers_policy /usr/libexec/sudo/sudoers.so\n'
            'Plugin sudoers_io sudoers.so\nPlugin sudoers_io sudoers.so\n'
            'Plugin python_io python_plugin.so a\nPlugin python_io python_plugin.so b\n')
    assert [p['outcome'] for p in r['plugins']] == ['loaded', 'ignored_duplicate', 'loaded', 'ignored_duplicate',
                                                    'loaded', 'loaded_clone', 'loaded_if_present']
    assert r['status'] == 'loads' and r['complete']


def test_configured_io_plugin_suppresses_the_default_io_plugin():
    r = run('Plugin audit_json audit_json.so logfile=/var/log/sudo.json\nPlugin python_io python_plugin.so\n')
    assert [(p['symbol'], p['source']) for p in r['plugins']] == [
        ('audit_json', sc.CONF_PATH), ('python_io', sc.CONF_PATH), ('sudoers_policy', 'default'),
        ('sudoers_audit', 'default')]


def test_unpackaged_object_with_a_packaged_symbol_is_unresolved():
    r = run('Plugin sudoers_policy /tmp/evil/sudoers.so\n')
    assert r['plugins'][0]['type'] is None and r['plugins'][0]['type_basis'] == 'unresolved'
    assert not r['complete']


def test_line_syntax_matches_sudo_parseln():
    text = ('  plugin\tsudoers_policy  sudoers.so \\\n   a=1 # b=2 \\\n'
            'Plugin only_one_field\nPluginx x y\nPlugin\nSet probe_interfaces false\n'
            'Path NOEXEC /a /b\t\r\nPath askpass /bin/ask\nPath askpass\nPath bogus /x\n'
            'Debug sudo /var/log/sudo_debug all@info  extra\nDebug sudo /x\n')
    p = sc.parse(text)
    assert p['plugins'] == [{'line': 2, 'symbol': 'sudoers_policy', 'path': 'sudoers.so', 'options': ['a=1']}]
    assert p['paths']['noexec']['value'] == '/a /b' and p['paths']['askpass'] == {'value': None,
                                                                                 'source': sc.CONF_PATH, 'line': 9}
    assert p['debug'] == [{'line': 11, 'program': 'sudo', 'file': '/var/log/sudo_debug', 'flags': 'all@info  extra'}]


def test_continuation_to_end_of_file_and_ascii_only_case_folding():
    assert sc.parse('Plugin a \\\nb')['plugins'][0]['path'] == 'b'
    assert sc.parse('Plugin a b\\')['plugins'][0]['path'] == 'b'
    assert sc.parse('PLUGİN a b\n')['plugins'] == []
    assert sc.parse('Plugin a b \\\\\nPlugin c d\n')['plugins'][0]['options'] == ['\\\\']


def test_relative_path_values_are_reported_but_not_blocking():
    r = run('Path sesh bin/sesh\n')
    assert r['paths']['sesh']['absolute'] is False and r['complete']
    assert [g['code'] for g in r['gaps']] == ['relative_path_value']


def test_fail_closed_inputs():
    assert run('Plugin a b\0\n')['gaps'][0]['code'] == 'binary'
    big = run('#' * (sc.MAX_TEXT + 1))
    assert big['status'] == 'unresolved' and not big['complete']
    bad = run(b'Plugin sudoers_policy sudoers.so \xff\n')
    assert not bad['complete'] and 'invalid_utf8' in {g['code'] for g in bad['gaps']}
    many = run(''.join('Plugin sudoers_io sudoers.so\n' for _ in range(sc.MAX_PLUGINS + 5)))
    assert 'plugins_truncated' in {g['code'] for g in many['gaps']} and not many['complete']


def test_result_is_stable_and_hashes_inputs():
    a, b = run('Plugin sudoers_policy sudoers.so\n'), run('Plugin sudoers_policy sudoers.so\n')
    assert a == b and len(a['text_sha256']) == 64 and len(a['plugins'][0]['resolved_path_sha256']) == 64


def test_path_names_fold_only_ascii_and_overlong_plugin_paths_are_fatal():
    assert sc.parse('Path asKpass /bin/x\n')['paths']['askpass']['value'] is None
    assert sc.parse('Path ASKPASS /bin/x\n')['paths']['askpass']['value'] == '/bin/x'
    r = run('Plugin sudoers_policy /' + 'a' * (sc.PATH_MAX - 1) + '\n')
    assert r['status'] == 'fails' and r['fatal'] == 'path_too_long' and not r['plugins'][0]['code_runs']
    assert run('Plugin sudoers_policy /' + 'a' * (sc.PATH_MAX - 2) + '\n')['fatal'] is None
