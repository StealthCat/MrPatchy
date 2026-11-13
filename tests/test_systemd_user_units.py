"""Per-user (systemd --user) resolution in the pure systemd unit contract (#702)."""
from app import systemd_units as su

HOME = '/home/alice'
RUN = '/run/user/1000'
CONF = f'{HOME}/.config/systemd/user'
DATA = f'{HOME}/.local/share/systemd/user'
VENDOR = '/usr/lib/systemd/user'
ETC = '/etc/systemd/user'
TABLE, _ = su.user_search_paths(HOME, RUN)
ALL = [root for root, _ in TABLE]
SVC = '[Service]\nExecStart=/usr/bin/agent\n[Install]\nWantedBy=default.target\n'


def f(path, text):
    return {'path': path, 'kind': 'file', 'text': text}


def ln(path, target):
    return {'path': path, 'kind': 'symlink', 'target': target}


def run(obs, roots=ALL, home=HOME, runtime=RUN, account='alice'):
    r = su.resolve_user(obs, home, runtime, account, collected_roots=roots)
    return r, {u['name']: u for u in r['units']}


def test_user_table_follows_documented_precedence():
    roots = [root for root, _ in TABLE]
    assert roots[0] == f'{HOME}/.config/systemd/user.control'
    assert roots[-1] == f'{RUN}/systemd/generator.late'
    order = [f'{RUN}/systemd/transient', CONF, '/etc/xdg/systemd/user', ETC,
             f'{RUN}/systemd/user', '/run/systemd/user', DATA,
             '/usr/local/share/systemd/user', '/usr/share/systemd/user',
             '/usr/local/lib/systemd/user', VENDOR]
    assert [roots.index(x) for x in order] == sorted(roots.index(x) for x in order)
    origins = dict(TABLE)
    assert origins[CONF] == origins[DATA] == 'user' and origins[ETC] == 'administrator'
    assert origins[VENDOR] == 'vendor' and origins[f'{RUN}/systemd/generator'] == 'generated'


def test_home_unit_is_custom_user_origin_running_as_account():
    r, u = run([f(f'{CONF}/agent.service', '[Service]\nExecStart=/usr/bin/agent\nUser=root\n[Install]\nWantedBy=default.target\n'),
                ln(f'{CONF}/default.target.wants/agent.service', f'{CONF}/agent.service')])
    a = u['agent.service']
    assert a['origin'] == 'user' and a['classification'] == 'custom' and a['state'] == 'enabled'
    assert a['account'] == {'user': 'alice', 'group': None, 'manager': 'user', 'declared_user': 'root'}
    assert {'code': 'user_unit_declared_user', 'path': f'{CONF}/agent.service', 'detail': 'root'} in r['gaps']
    assert r['scope'] == 'user' and r['account'] == 'alice' and not r['complete']


def test_home_override_of_vendor_user_unit_is_reported():
    _, u = run([f(f'{VENDOR}/agent.service', SVC),
                f(f'{CONF}/agent.service', '[Service]\nExecStart=/home/alice/x\n')])
    a = u['agent.service']
    assert a['fragment'] == f'{CONF}/agent.service'
    assert a['shadowed'] == [{'path': f'{VENDOR}/agent.service', 'origin': 'vendor'}]
    assert a['classification'] == 'vendor_overridden' and a['exec']['ExecStart'] == ['/home/alice/x']


def test_home_dropin_overrides_vendor_and_global_admin_dropin():
    r, u = run([f(f'{VENDOR}/agent.service', SVC),
                f(f'{ETC}/agent.service.d/10-x.conf', '[Service]\nExecStart=\nExecStart=/etc/x\n'),
                f(f'{CONF}/agent.service.d/10-x.conf', '[Service]\nExecStart=\nExecStart=/home/y\n')])
    a = u['agent.service']
    assert a['dropins'] == [{'path': f'{CONF}/agent.service.d/10-x.conf', 'origin': 'user', 'scope': 'unit'}]
    assert a['exec']['ExecStart'] == ['/home/y'] and a['override_origins'] == ['user']
    assert r['complete'] and a['state'] == 'disabled'


def test_vendor_user_unit_enabled_globally_and_masked_per_user():
    _, u = run([f(f'{VENDOR}/agent.service', SVC),
                ln(f'{ETC}/default.target.wants/agent.service', f'{VENDOR}/agent.service')])
    assert u['agent.service']['state'] == 'enabled'
    assert u['agent.service']['enabled_by'][0]['origin'] == 'administrator'
    _, u = run([f(f'{VENDOR}/agent.service', SVC), ln(f'{CONF}/agent.service', '/dev/null')])
    assert u['agent.service']['state'] == 'masked' and u['agent.service']['exec'] == {}


def test_user_timer_relationship_and_runtime_transient():
    r, u = run([f(f'{DATA}/sync.timer', '[Timer]\nOnCalendar=hourly\n'),
                f(f'{RUN}/systemd/transient/run-u1.service', '[Service]\nExecStart=/bin/true\n')])
    assert u['sync.timer']['origin'] == 'user'
    assert r['triggers'] == [{'trigger': 'sync.timer', 'type': 'timer', 'unit': 'sync.service',
                              'explicit': False, 'unit_present': False, 'unit_state': 'missing',
                              'schedule': {'OnCalendar': ['hourly']}}]
    assert any(g['code'] == 'trigger_target_missing' for g in r['gaps'])
    assert u['run-u1.service']['state'] == 'transient'


def test_exec_prefix_does_not_claim_root_privilege():
    _, u = run([f(f'{CONF}/p.service', '[Service]\nExecStart=+/usr/bin/x\n')])
    assert u['p.service']['privileged_exec'] is False


def test_system_paths_are_not_user_units():
    r, u = run([f('/etc/systemd/system/agent.service', SVC)])
    assert u == {} and {'code': 'outside_search_path', 'path': '/etc/systemd/system/agent.service',
                        'detail': ''} in r['gaps']


def test_invalid_home_runtime_account_and_uncollected_dirs_are_gaps():
    r, _ = run([f(f'{VENDOR}/agent.service', SVC)], roots=[VENDOR], home='relative/home',
               runtime='/run/user/../0', account='')
    codes = {g['code'] for g in r['gaps']}
    assert {'user_home_invalid', 'user_runtime_dir_invalid', 'user_account_invalid',
            'search_path_not_collected'} <= codes
    assert not any(p['path'].startswith('relative') or '/run/user' in p['path'] for p in r['search_paths'])
    assert r['account'] is None and not r['complete']


def test_runtime_dir_colliding_with_system_root_is_rejected():
    table, gaps = su.user_search_paths(HOME, '/run')
    assert '/run/systemd/user' not in [root for root, _ in table]
    assert {'code': 'user_search_path_conflict', 'path': '/run/systemd/user', 'detail': ''} in gaps


def test_deterministic_digest_and_system_resolution_unchanged():
    obs = [f(f'{CONF}/agent.service', SVC)]
    assert run(obs)[0]['digest'] == run(list(obs))[0]['digest']
    system = su.resolve([f('/usr/lib/systemd/system/a.service', SVC)],
                        collected_roots=[root for root, _ in su.SEARCH_PATHS])
    assert 'scope' not in system and system['complete']
    assert system['units'][0]['account'] == {'user': None, 'group': None}
