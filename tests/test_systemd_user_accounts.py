"""Account enumeration for per-user systemd managers (#702)."""
from app import systemd_units
from app.systemd_user_accounts import (
    DEFAULT_UID_MAX, DEFAULT_UID_MIN, MAX_PASSWD_LINES, candidate_accounts, parse_login_defs, parse_passwd,
)

PASSWD = '\n'.join([
    'root:x:0:0:root:/root:/bin/bash',
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
    'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
    'svc:x:998:998:Service Account,,,:/var/lib/svc:/usr/sbin/nologin',
    'alice:$6$secret-hash$xyz:1000:1000:Alice Example,,,:/home/alice:/bin/bash',
    'bob:x:1001:1001::/home/bob:',
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin',
]) + '\n'


def _codes(result):
    return [g['code'] for g in result['gaps']]


def test_login_defs_reads_range_and_defaults():
    parsed = parse_login_defs('# comment\nUID_MIN\t\t 2000\nUID_MAX 50000\nGID_MIN 2000\n')
    assert (parsed['uid_min'], parsed['uid_max'], parsed['defaulted'], parsed['complete']) == (2000, 50000, [], True)
    empty = parse_login_defs('')
    assert (empty['uid_min'], empty['uid_max']) == (DEFAULT_UID_MIN, DEFAULT_UID_MAX)
    assert empty['defaulted'] == ['UID_MIN', 'UID_MAX'] and empty['complete']
    missing = parse_login_defs(None)
    assert _codes(missing) == ['login_defs_not_collected'] and missing['uid_min'] == DEFAULT_UID_MIN


def test_login_defs_rejects_unparsed_values_without_guessing():
    octal = parse_login_defs('UID_MIN 01000\n')
    assert _codes(octal) == ['login_defs_value_invalid']
    assert octal['uid_min'] == DEFAULT_UID_MIN and octal['defaulted'] == ['UID_MIN', 'UID_MAX'] and not octal['complete']
    inverted = parse_login_defs('UID_MIN 5000\nUID_MAX 4000\n')
    assert 'login_defs_range_invalid' in _codes(inverted)
    assert (inverted['uid_min'], inverted['uid_max']) == (DEFAULT_UID_MIN, DEFAULT_UID_MAX)
    past_default = parse_login_defs('UID_MIN 70000\n')
    assert 'login_defs_range_invalid' in _codes(past_default) and past_default['uid_min'] == DEFAULT_UID_MIN
    duplicate = parse_login_defs('UID_MIN 1500\nUID_MIN 1600\n')
    assert duplicate['uid_min'] == 1600 and _codes(duplicate) == ['login_defs_duplicate_key']


def test_passwd_parsing_drops_password_and_gecos():
    parsed = parse_passwd(PASSWD)
    assert parsed['complete'] and len(parsed['accounts']) == 7
    alice = next(a for a in parsed['accounts'] if a['name'] == 'alice')
    assert alice == {'name': 'alice', 'uid': 1000, 'gid': 1000, 'home': '/home/alice', 'shell': '/bin/bash'}
    assert 'secret-hash' not in repr(parsed) and 'Alice Example' not in repr(parsed)


def test_passwd_malformed_entries_are_gaps_and_never_echo_lines():
    text = '\n'.join([
        'broken-line-with-$6$hash',
        'bad name:x:1002:1002::/home/x:/bin/sh',
        'carol:x:-1:1003::/home/carol:/bin/sh',
        'dave:x:1004:1004::home/dave:/bin/sh',
        'erin:x:1005:1005::/home/erin:/bin/sh',
        'erin:x:1006:1006::/srv/erin:/bin/sh',
        'erin:x:1007:1007::/opt/erin:/bin/sh',
    ])
    parsed = parse_passwd(text)
    assert _codes(parsed) == ['passwd_line_malformed', 'passwd_name_invalid', 'passwd_id_invalid',
                              'passwd_duplicate_name']
    assert '$6$hash' not in repr(parsed)
    assert [a['name'] for a in parsed['accounts']] == ['dave']
    assert parsed['accounts'][0]['home'] is None and not parsed['complete']


def test_passwd_caps_and_non_text():
    assert _codes(parse_passwd(None)) == ['passwd_not_collected']
    big = 'u:x:1:1::/:/bin/sh\n' * (MAX_PASSWD_LINES + 1)
    over = parse_passwd(big)
    assert _codes(over) == ['passwd_too_many_lines'] and over['accounts'] == []


def test_candidates_are_root_regular_and_lingering_accounts():
    result = candidate_accounts(parse_passwd(PASSWD), parse_login_defs(''),
                                {'accounts': ['svc'], 'complete': True})
    assert result['complete'] and result['uid_range'] == [1000, 60000]
    by = {a['account']: a for a in result['accounts']}
    assert sorted(by) == ['alice', 'bob', 'root', 'svc']
    assert by['root']['reasons'] == ['root'] and by['root']['default_runtime_dir'] == '/run/user/0'
    assert by['alice']['reasons'] == ['regular_uid'] and by['alice']['interactive_shell'] is True
    assert by['bob']['interactive_shell'] is True  # empty shell field means /bin/sh
    assert by['svc'] == {'account': 'svc', 'uid': 998, 'home': '/var/lib/svc', 'lingering': True,
                         'interactive_shell': False, 'default_runtime_dir': '/run/user/998',
                         'reasons': ['lingering']}


def test_candidates_report_upstream_gaps_and_unknown_lingering_accounts():
    result = candidate_accounts(parse_passwd(PASSWD + 'zed:x:2000:2000::/:/bin/sh\n'), parse_login_defs(None),
                                {'accounts': ['ghost'], 'complete': False})
    codes = _codes(result)
    assert codes == ['login_defs_incomplete', 'linger_incomplete', 'linger_account_unknown', 'account_home_invalid']
    assert result['gaps'][2]['detail'] == 'ghost' and not result['complete']
    zed = next(a for a in result['accounts'] if a['account'] == 'zed')
    assert zed['home'] is None
    no_linger = candidate_accounts(parse_passwd(PASSWD), parse_login_defs(''), None)
    assert _codes(no_linger) == ['linger_not_collected']
    assert _codes(candidate_accounts(None, None, None)) == ['passwd_not_collected']
    partial = candidate_accounts(parse_passwd('bad\n' + PASSWD), parse_login_defs(''), {'accounts': [], 'complete': True})
    assert _codes(partial) == ['passwd_incomplete']


def test_candidates_drop_and_report_names_sharing_one_uid():
    passwd = parse_passwd('root:x:0:0:r:/root:/bin/bash\ntoor:x:0:0:r:/root:/bin/sh\n'
                          'alice:x:1000:1000::/home/alice:/bin/bash\n'
                          'alias:x:1000:1000::/srv/alias:/bin/bash\n'
                          'carol:x:1002:1002::/home/carol:/bin/bash\n'
                          'svc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n'
                          'svc2:x:998:998::/var/lib/svc2:/usr/sbin/nologin\n')
    assert passwd['complete']
    result = candidate_accounts(passwd, parse_login_defs(''), {'accounts': [], 'complete': True})
    assert [a['account'] for a in result['accounts']] == ['carol']
    assert result['gaps'] == [{'code': 'passwd_duplicate_uid', 'detail': '1000: alias,alice'},
                              {'code': 'passwd_duplicate_uid', 'detail': '0: root,toor'}]
    assert not result['complete']
    # svc/svc2 share UID 998 but neither is a candidate (not root, outside the range, not lingering),
    # so the exact gap list above holds no 998 entry; once one of them lingers the UID is ambiguous.
    lingering = candidate_accounts(passwd, parse_login_defs(''), {'accounts': ['svc'], 'complete': True})
    assert {'code': 'passwd_duplicate_uid', 'detail': '998: svc,svc2'} in lingering['gaps']
    assert 'svc' not in [a['account'] for a in lingering['accounts']]


def test_candidates_compose_with_resolve_user():
    result = candidate_accounts(parse_passwd(PASSWD), parse_login_defs(''), {'accounts': [], 'complete': True})
    alice = next(a for a in result['accounts'] if a['account'] == 'alice')
    table, gaps = systemd_units.user_search_paths(alice['home'], alice['default_runtime_dir'])
    assert gaps == []
    assert ('/home/alice/.config/systemd/user', 'user') in table
    assert ('/run/user/1000/systemd/user.control', 'runtime') in table
