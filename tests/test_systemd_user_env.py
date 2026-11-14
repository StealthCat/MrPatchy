"""Pure user-manager environment and linger parsers (roadmap F, #702)."""
from app import systemd_user_env as env


def _codes(result):
    return [g['code'] for g in result['gaps']]


def test_plain_environment_maps_documented_keys_only():
    text = (
        'HOME=/home/alice\n'
        'LANG=C.UTF-8\n'
        'XDG_RUNTIME_DIR=/run/user/1000\n'
        'XDG_CONFIG_HOME=/home/alice/.cfg\n'
        'XDG_DATA_DIRS=/opt/share:/usr/share\n'
        'AWS_SECRET_ACCESS_KEY=hunter2\n'
    )
    r = env.parse_manager_environment(text)
    assert r['complete'] is True and r['gaps'] == []
    assert r['home'] == '/home/alice'
    assert r['runtime_dir'] == '/run/user/1000'
    assert r['xdg'] == {'config_home': '/home/alice/.cfg', 'data_dirs': '/opt/share:/usr/share'}
    assert 'hunter2' not in repr(r)


def test_dollar_quoted_values_decode_systemd_escapes():
    text = (
        "HOME=$'/home/al ice'\n"
        "XDG_RUNTIME_DIR=/run/user/1000\n"
        "XDG_DATA_HOME=$'/home/al ice/d\\'q\\\\x\\x41\\101\\303\\251'\n"
    )
    r = env.parse_manager_environment(text)
    assert r['complete'] is True, r['gaps']
    assert r['home'] == '/home/al ice'
    assert r['xdg']['data_home'] == "/home/al ice/d'q\\xAAé"


def test_undecodable_or_control_values_are_gaps_and_never_guessed():
    text = (
        "HOME=/home/a\n"
        "XDG_RUNTIME_DIR=/run/user/1\n"
        "XDG_CONFIG_HOME=$'/x\\q'\n"        # unsupported escape
        "XDG_CACHE_HOME=$'/x\n"             # unterminated quote
        "XDG_DATA_HOME=$'/x\\ny'\n"         # newline in value
        "XDG_CONFIG_DIRS=$'/x\\377'\n"      # invalid UTF-8
    )
    r = env.parse_manager_environment(text)
    assert r['complete'] is False
    assert r['xdg'] == {}
    codes = _codes(r)
    assert codes.count('env_value_undecodable') == 3
    assert 'env_value_invalid' in codes


def test_malformed_lines_never_echo_content_and_duplicates_drop_the_key():
    text = (
        'HOME=/home/a\n'
        'XDG_RUNTIME_DIR=/run/user/1\n'
        'not a variable secret-token\n'
        '1BAD=secret-token\n'
        'XDG_DATA_HOME=/home/a/one\n'
        'XDG_DATA_HOME=/home/a/two\n'
        'XDG_DATA_HOME=/home/a/three\n'
    )
    r = env.parse_manager_environment(text)
    assert 'secret-token' not in repr(r)
    assert _codes(r).count('env_line_malformed') == 2
    assert _codes(r).count('env_duplicate_key') == 2
    assert 'data_home' not in r['xdg']
    assert r['complete'] is False


def test_missing_home_runtime_and_empty_xdg_values():
    r = env.parse_manager_environment('XDG_CONFIG_HOME=\nHOME=\n')
    assert r['home'] is None and r['runtime_dir'] is None and r['xdg'] == {}
    assert {'env_home_missing', 'env_runtime_dir_missing'} <= set(_codes(r))


def test_uncollected_and_over_cap_environment():
    assert _codes(env.parse_manager_environment(None)) == ['env_not_collected']
    big = 'A=' + 'x' * env.MAX_ENV_BYTES
    assert _codes(env.parse_manager_environment(big)) == ['env_too_large']
    many = 'A=1\n' * (env.MAX_ENV_LINES + 1)
    r = env.parse_manager_environment(many)
    assert _codes(r) == ['env_too_many_lines'] and r['complete'] is False


def test_nul_in_any_line_is_a_gap():
    r = env.parse_manager_environment('HOME=/h\nXDG_RUNTIME_DIR=/r\nHOME2=a\x00b\n')
    assert _codes(r) == ['env_value_invalid'] and r['home'] == '/h'


def test_linger_listing_accepts_valid_accounts_only():
    r = env.parse_linger(['bob', 'alice', 'svc.web', 'bob', '../etc', '-x', '1000', '', 'a' * 33, 7])
    assert r['accounts'] == ['alice', 'bob', 'svc.web']
    assert _codes(r).count('linger_entry_invalid') == 6
    assert r['complete'] is False
    assert env.parse_linger([]) == {'contract_version': 1, 'accounts': [], 'gaps': [], 'complete': True}


def test_linger_uncollected_and_over_cap():
    for value in (None, 'alice', b'alice', 5):
        assert _codes(env.parse_linger(value)) == ['linger_not_collected']
    r = env.parse_linger(f'u{i}' for i in range(env.MAX_LINGER_ENTRIES + 5))
    assert len(r['accounts']) == env.MAX_LINGER_ENTRIES
    assert _codes(r) == ['linger_too_many_entries']


def test_outputs_match_resolve_user_inputs():
    from app import systemd_units
    r = env.parse_manager_environment('HOME=/home/a\nXDG_RUNTIME_DIR=/run/user/1\n')
    table, gaps = systemd_units.user_search_paths(r['home'], r['runtime_dir'])
    assert gaps == [] and ('/home/a/.config/systemd/user', 'user') in table
