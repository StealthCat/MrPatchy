"""Non-default XDG directories for per-user (systemd --user) resolution (#702)."""
from app import systemd_units as su

HOME = '/home/alice'
RUN = '/run/user/1000'
SVC = '[Service]\nExecStart=/usr/bin/agent\n[Install]\nWantedBy=default.target\n'
XDG = {'config_home': '/srv/alice/conf', 'data_home': '/srv/alice/data', 'cache_home': '/srv/alice/cache',
       'config_dirs': '/opt/site/etc/xdg:/etc/xdg/', 'data_dirs': ['/opt/apps/share', '/usr/share']}


def f(path, text):
    return {'path': path, 'kind': 'file', 'text': text}


def roots(table):
    return [root for root, _ in table]


def run(obs, xdg, home=HOME):
    table, _ = su.user_search_paths(home, RUN, xdg)
    r = su.resolve_user(obs, home, RUN, 'alice', collected_roots=roots(table), xdg=xdg)
    return r, {u['name']: u for u in r['units']}


def test_defaults_unchanged_without_xdg():
    assert su.user_search_paths(HOME, RUN) == su.user_search_paths(HOME, RUN, None)
    assert su.user_search_paths(HOME, RUN) == su.user_search_paths(HOME, RUN, {
        'config_home': '', 'data_home': None, 'config_dirs': '', 'data_dirs': []})
    explicit = {'config_home': f'{HOME}/.config', 'data_home': f'{HOME}/.local/share',
                'config_dirs': '/etc/xdg', 'data_dirs': '/usr/local/share/:/usr/share/'}
    assert su.user_search_paths(HOME, RUN, explicit) == su.user_search_paths(HOME, RUN)


def test_supplied_xdg_dirs_follow_documented_order():
    table, gaps = su.user_search_paths(HOME, RUN, XDG)
    assert gaps == []
    order = ['/srv/alice/conf/systemd/user.control', f'{RUN}/systemd/user.control',
             '/srv/alice/conf/systemd/user', '/opt/site/etc/xdg/systemd/user', '/etc/xdg/systemd/user',
             '/etc/systemd/user', f'{RUN}/systemd/user', '/srv/alice/data/systemd/user',
             '/opt/apps/share/systemd/user', '/usr/share/systemd/user', '/usr/lib/systemd/user']
    rs = roots(table)
    assert [rs.index(x) for x in order] == sorted(rs.index(x) for x in order)
    assert not any(x.startswith(HOME) for x in rs)
    assert '/usr/local/share/systemd/user' not in rs
    origins = dict(table)
    assert origins['/srv/alice/conf/systemd/user'] == origins['/srv/alice/data/systemd/user'] == 'user'
    assert origins['/opt/site/etc/xdg/systemd/user'] == 'administrator'
    assert origins['/opt/apps/share/systemd/user'] == 'local' and origins['/usr/share/systemd/user'] == 'vendor'


def test_unit_in_custom_config_home_overrides_vendor_and_is_enabled():
    r, u = run([f('/usr/lib/systemd/user/agent.service', SVC),
                f('/srv/alice/conf/systemd/user/agent.service', SVC.replace('agent\n', 'agent --custom\n')),
                {'path': '/srv/alice/conf/systemd/user/default.target.wants/agent.service', 'kind': 'symlink',
                 'target': '/srv/alice/conf/systemd/user/agent.service'}], XDG)
    a = u['agent.service']
    assert a['origin'] == 'user' and a['config']['Service']['ExecStart'] == ['/usr/bin/agent --custom']
    assert a['shadowed'] == [{'path': '/usr/lib/systemd/user/agent.service', 'origin': 'vendor'}]
    assert a['state'] == 'enabled' and a['enabled_by'][0]['origin'] == 'user'
    # A unit in the default home directory is outside this manager's search table.
    r2, u2 = run([f(f'{HOME}/.config/systemd/user/other.service', SVC)], XDG)
    assert 'other.service' not in u2


def test_config_and_cache_home_drive_specifiers():
    _, u = run([f('/srv/alice/conf/systemd/user/s.service', '[Service]\nExecStart=/bin/s %E %C %h\n')], XDG)
    assert u['s.service']['expanded']['Service']['ExecStart'] == ['/bin/s /srv/alice/conf /srv/alice/cache /home/alice']
    # Valid XDG homes still expand when the account home itself is invalid.
    _, u = run([f('/srv/alice/conf/systemd/user/s.service', '[Service]\nExecStart=/bin/s %E %C\nExecStop=/bin/s %h\n')],
               XDG, home='relative')
    svc = u['s.service']['expanded']['Service']
    assert svc['ExecStart'] == ['/bin/s /srv/alice/conf /srv/alice/cache'] and svc['ExecStop'] == ['/bin/s %h']


def test_invalid_xdg_values_are_gaps_and_never_defaulted():
    bad = {'config_home': 'relative/conf', 'data_home': '/srv/../data', 'cache_home': '/tmp/x\n',
           'config_dirs': ['/opt/ok', 'rel', 7], 'data_dirs': 42, 'XDG_STATE_HOME': '/x'}
    table, gaps = su.user_search_paths(HOME, RUN, bad)
    codes = [g['code'] for g in gaps]
    for code in ('xdg_config_home_invalid', 'xdg_data_home_invalid', 'xdg_cache_home_invalid',
                 'xdg_config_dirs_invalid', 'xdg_data_dirs_invalid', 'xdg_unknown_key'):
        assert code in codes
    assert codes.count('xdg_config_dirs_invalid') == 2
    rs = roots(table)
    # No guessed default replaces an invalid value.
    assert not any(x.startswith(HOME) for x in rs)
    assert '/etc/xdg/systemd/user' not in rs and '/usr/share/systemd/user' not in rs
    assert '/opt/ok/systemd/user' in rs and '/usr/lib/systemd/user' in rs
    r, u = run([f('/opt/ok/systemd/user/s.service', '[Service]\nExecStart=/bin/s %E %C\n')], bad)
    assert not r['complete'] and {'xdg_config_home_invalid', 'xdg_unknown_key'} <= {g['code'] for g in r['gaps']}
    assert u['s.service']['expanded']['Service']['ExecStart'] == ['/bin/s %E %C']
    _, gaps = su.user_search_paths(HOME, RUN, ['not', 'a', 'mapping'])
    assert {'code': 'xdg_invalid', 'path': '', 'detail': ''} in gaps


def test_xdg_dir_caps_and_conflicts_are_reported():
    many = ':'.join(f'/opt/d{i}' for i in range(su.MAX_XDG_DIRS + 5))
    table, gaps = su.user_search_paths(HOME, RUN, {'data_dirs': many})
    assert {'code': 'xdg_data_dirs_cap', 'path': '', 'detail': f'{su.MAX_XDG_DIRS + 5} > {su.MAX_XDG_DIRS}'} in gaps
    assert f'/opt/d{su.MAX_XDG_DIRS - 1}/systemd/user' in roots(table)
    assert f'/opt/d{su.MAX_XDG_DIRS}/systemd/user' not in roots(table)
    # XDG_CONFIG_DIRS=/etc would place /etc/systemd/user twice; both copies are rejected.
    table, gaps = su.user_search_paths(HOME, RUN, {'config_dirs': '/etc'})
    assert '/etc/systemd/user' not in roots(table)
    assert {'code': 'user_search_path_conflict', 'path': '/etc/systemd/user', 'detail': ''} in gaps


def test_system_resolution_unchanged():
    system = su.resolve([f('/usr/lib/systemd/system/a.service', SVC)],
                        collected_roots=[root for root, _ in su.SEARCH_PATHS])
    assert system['complete'] and 'scope' not in system
