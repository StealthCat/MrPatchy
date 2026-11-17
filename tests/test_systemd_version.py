"""Version-gated systemd specifier expansion in the pure unit contract (#702).

Upstream systemd NEWS: 228 made %u/%U/%h/%s always resolve to the manager's
user (older releases used User=); 236 added %S/%C/%L; 239 added %E and %j/%J;
240 added %g/%G. A supplied version must never expand a specifier the release
did not support with its current meaning.
"""
import pytest

from app import systemd_units as su

ETC = '/etc/systemd/system'
ALL = [root for root, _ in su.SEARCH_PATHS]
SVC = ('[Service]\nUser=app\nExecStart=/usr/bin/app --user %u --uid %U --home %h --shell %s '
       '--group %g --gid %G\nExecStartPre=/usr/bin/prep %S %C %L %E\nExecStop=/bin/kill %n %j\n')
OBS = [{'path': f'{ETC}/web-api.service', 'kind': 'file', 'text': SVC}]


def unit(result):
    return {u['name']: u for u in result['units']}['web-api.service']


def gap_letters(result):
    return [g['detail'] for g in result['gaps'] if g['code'] == 'unexpanded_specifier']


@pytest.mark.parametrize('text,version,package', [
    ('systemd 252 (252.22-1~deb12u1)\n+PAM +AUDIT +SELINUX\ndefault-hierarchy=unified\n', 252, '252.22-1~deb12u1'),
    ('systemd 219\n+PAM +AUDIT\n', 219, None),
    ('systemd 245 (245.4-4ubuntu3.24)\r\n', 245, '245.4-4ubuntu3.24'),
])
def test_parse_systemctl_version_output(text, version, package):
    assert su.parse_systemd_version(text) == {'version': version, 'package_version': package, 'gaps': []}


@pytest.mark.parametrize('text', [
    None, b'systemd 252', '', 'systemd', 'systemd x', 'systemd 0', 'systemd 0252', 'systemd 12345',
    'Systemd 252', 'systemd 252 extra', 'systemd  252', 'systemd 252 ()', 'systemd 252\x00',
    'systemd 252 (a\x01b)', 'x' * (su.MAX_VERSION_TEXT + 1), '\nsystemd 252',
])
def test_malformed_version_output_is_a_gap_not_a_guess(text):
    parsed = su.parse_systemd_version(text)
    assert parsed['version'] is None and parsed['package_version'] is None
    assert parsed['gaps'] and parsed['gaps'][0]['code'].startswith('systemd_version_')


def test_omitted_version_keeps_existing_output_and_digest():
    before = su.resolve(OBS, collected_roots=ALL)
    assert 'systemd_version' not in before
    assert unit(before)['expanded']['Service']['ExecStart'] == [
        '/usr/bin/app --user root --uid 0 --home /root --shell /bin/sh --group root --gid 0']
    assert any(item.startswith('System %u/%U/%h/%s') for item in before['limitations'])
    assert su.resolve(OBS, collected_roots=ALL, systemd_version=None)['digest'] == before['digest']


def test_current_release_expands_everything_and_settles_the_user_limitation():
    r = su.resolve(OBS, collected_roots=ALL, systemd_version=252)
    u = unit(r)
    assert r['systemd_version'] == 252 and r['complete'] and u['specifiers'] == 'expanded'
    assert u['expanded']['Service']['ExecStartPre'] == ['/usr/bin/prep /var/lib /var/cache /var/log /etc']
    assert u['expanded']['Service']['ExecStop'] == ['/bin/kill web-api.service api']
    assert not any(item.startswith('System %u/%U/%h/%s') for item in r['limitations'])
    assert su.VERSION_LIMITATION_APPLIED in r['limitations']
    assert r['digest'] != su.resolve(OBS, collected_roots=ALL)['digest']


def test_release_before_228_never_resolves_user_specifiers_from_the_manager():
    # systemd 219 (EL7) resolved %u/%U/%h/%s from User=; guessing root would be wrong.
    r = su.resolve(OBS, collected_roots=ALL, systemd_version=219)
    u = unit(r)
    svc = u['expanded']['Service']
    assert svc['ExecStart'] == ['/usr/bin/app --user %u --uid %U --home %h --shell %s --group %g --gid %G']
    assert svc['ExecStartPre'] == ['/usr/bin/prep %S %C %L %E']
    assert svc['ExecStop'] == ['/bin/kill %n %j']  # never partially expanded
    assert u['specifiers'] == 'partial' and u['incomplete'] and not r['complete']
    assert gap_letters(r) == ['%C,%E,%G,%L,%S,%U,%g,%h,%j,%s,%u']


@pytest.mark.parametrize('version,withheld', [
    (227, set('uUhsSCLEjJgG')), (228, set('SCLEjJgG')), (235, set('SCLEjJgG')), (236, set('EjJgG')),
    (238, set('EjJgG')), (239, set('gG')), (240, set()), (9999, set()),
])
def test_each_specifier_is_gated_on_its_first_release(version, withheld):
    _, _, got = su._version_withheld(version)
    assert set(got) == withheld


@pytest.mark.parametrize('bad', [0, -1, 10000, 252.0, '252', True])
def test_invalid_supplied_version_withholds_all_and_is_a_gap(bad):
    r = su.resolve(OBS, collected_roots=ALL, systemd_version=bad)
    u = unit(r)
    assert r['systemd_version'] is None and not r['complete']
    assert any(g['code'] == 'systemd_version_invalid' for g in r['gaps'])
    assert u['expanded']['Service']['ExecStart'][0].startswith('/usr/bin/app --user %u')
    assert su.VERSION_LIMITATION_INVALID in r['limitations']


def test_user_manager_gates_home_account_and_config_specifiers():
    text = '[Service]\nExecStart=/usr/bin/sync --user %u --home %h --conf %E --cache %C --run %t\n'
    obs = [{'path': '/home/alice/.config/systemd/user/sync.service', 'kind': 'file', 'text': text}]
    roots = [p for p, _ in su.user_search_paths('/home/alice', '/run/user/1000')[0]]
    new = su.resolve_user(obs, '/home/alice', '/run/user/1000', 'alice', roots, systemd_version=255)
    old = su.resolve_user(obs, '/home/alice', '/run/user/1000', 'alice', roots, systemd_version=227)
    plain = su.resolve_user(obs, '/home/alice', '/run/user/1000', 'alice', roots)
    ex = {u['name']: u for u in new['units']}['sync.service']['expanded']['Service']['ExecStart']
    assert ex == ['/usr/bin/sync --user alice --home /home/alice --conf /home/alice/.config '
                  '--cache /home/alice/.cache --run /run/user/1000']
    assert new['complete'] and new['systemd_version'] == 255
    ox = {u['name']: u for u in old['units']}['sync.service']['expanded']['Service']['ExecStart']
    assert ox == [text.split('ExecStart=')[1].strip()]
    assert gap_letters(old) == ['%C,%E,%h,%u'] and not old['complete']
    assert 'systemd_version' not in plain and plain['complete']
