from app import systemd_units as su

ALL = [root for root, _ in su.SEARCH_PATHS]
VENDOR = '/usr/lib/systemd/system'
ETC = '/etc/systemd/system'


def f(path, text):
    return {'path': path, 'kind': 'file', 'text': text}


def ln(path, target):
    return {'path': path, 'kind': 'symlink', 'target': target}


def run(obs, roots=ALL):
    r = su.resolve(obs, collected_roots=roots)
    return r, {u['name']: u for u in r['units']}


SVC = '[Unit]\nDescription=Demo\n[Service]\nExecStart=/usr/bin/demo --a\nUser=demo\n[Install]\nWantedBy=multi-user.target\n'


def test_vendor_unit_disabled_and_not_package_verified():
    r, u = run([f(f'{VENDOR}/demo.service', SVC)])
    d = u['demo.service']
    assert d['state'] == 'disabled' and d['origin'] == 'vendor'
    assert d['classification'] == 'vendor_location' and d['package_verified'] is False
    assert d['exec'] == {'ExecStart': ['/usr/bin/demo --a']}
    assert d['account'] == {'user': 'demo', 'group': None}
    assert r['complete'] and r['runtime_state'] == 'not_collected'


def test_etc_fragment_shadows_vendor_and_is_override():
    r, u = run([f(f'{VENDOR}/demo.service', SVC),
                f(f'{ETC}/demo.service', '[Service]\nExecStart=/opt/evil\n')])
    d = u['demo.service']
    assert d['fragment'] == f'{ETC}/demo.service'
    assert d['shadowed'] == [{'path': f'{VENDOR}/demo.service', 'origin': 'vendor'}]
    assert d['exec']['ExecStart'] == ['/opt/evil']
    assert d['classification'] == 'vendor_overridden' and d['state'] == 'static'


def test_control_and_transient_outrank_etc():
    _, u = run([f(f'{ETC}/a.service', '[Service]\nExecStart=/etc\n'),
                f('/run/systemd/transient/a.service', '[Service]\nExecStart=/t\n')])
    assert u['a.service']['origin'] == 'transient' and u['a.service']['state'] == 'transient'
    assert u['a.service']['exec']['ExecStart'] == ['/t']


def test_mask_by_dev_null_symlink_and_empty_file():
    _, u = run([f(f'{VENDOR}/demo.service', SVC), ln(f'{ETC}/demo.service', '/dev/null'),
                f(f'{ETC}/demo.service.d/x.conf', '[Service]\nExecStart=/x\n'),
                f(f'{VENDOR}/b.service', SVC), f(f'{ETC}/b.service', '  \n')])
    for name in ('demo.service', 'b.service'):
        assert u[name]['state'] == 'masked' and u[name]['exec'] == {} and u[name]['dropins'] == []


def test_dropins_sorted_with_list_reset_and_same_name_shadowing():
    obs = [
        f(f'{VENDOR}/demo.service', SVC),
        f(f'{VENDOR}/demo.service.d/10-vendor.conf', '[Service]\nExecStartPre=/pre\n'),
        f(f'{ETC}/demo.service.d/20-override.conf', '[Service]\nExecStart=\nExecStart=/new\nUser=root\n'),
        f('/run/systemd/system/demo.service.d/10-vendor.conf', '[Service]\nExecStartPre=/runpre\n'),
    ]
    _, u = run(obs)
    d = u['demo.service']
    assert [x['path'] for x in d['dropins']] == [
        '/run/systemd/system/demo.service.d/10-vendor.conf', f'{ETC}/demo.service.d/20-override.conf']
    assert d['exec'] == {'ExecStart': ['/new'], 'ExecStartPre': ['/runpre']}
    assert d['account']['user'] == 'root'
    assert d['classification'] == 'vendor_overridden'
    assert d['override_origins'] == ['administrator', 'runtime']


def test_hierarchical_dropins_specificity_and_scopes():
    obs = [
        f(f'{VENDOR}/a-b-c.service', '[Service]\nExecStart=/base\n'),
        f(f'{ETC}/service.d/50.conf', '[Service]\nUser=typeuser\n'),
        f(f'{ETC}/a-.service.d/50.conf', '[Service]\nUser=prefixuser\n'),
        f(f'{ETC}/a-b-.service.d/40.conf', '[Service]\nGroup=g\n'),
        f(f'{ETC}/other.service.d/10.conf', '[Service]\nUser=nope\n'),
        f(f'{ETC}/a-b-c.service.d/readme.txt', 'ignored'),
    ]
    _, u = run(obs)
    d = u['a-b-c.service']
    assert d['account'] == {'user': 'prefixuser', 'group': 'g'}
    assert [x['scope'] for x in d['dropins']] == ['prefix', 'prefix']


def test_template_instance_uses_template_fragment_and_dropins():
    obs = [
        f(f'{VENDOR}/getty@.service', '[Service]\nExecStart=/sbin/agetty %I\n[Install]\nWantedBy=getty.target\n'),
        f(f'{ETC}/getty@.service.d/x.conf', '[Service]\nUser=t\n'),
        ln(f'{ETC}/getty.target.wants/getty@tty1.service', f'{VENDOR}/getty@.service'),
    ]
    _, u = run(obs)
    inst = u['getty@tty1.service']
    assert inst['instance'] == 'tty1' and inst['fragment'] == f'{VENDOR}/getty@.service'
    assert inst['state'] == 'enabled' and inst['account']['user'] == 't'
    assert [x['scope'] for x in inst['dropins']] == ['template']
    assert u['getty@.service']['template'] is True


def test_enablement_links_vendor_static_dependencies_and_foreign_targets():
    obs = [
        f(f'{VENDOR}/demo.service', SVC),
        ln(f'{ETC}/multi-user.target.wants/demo.service', f'{VENDOR}/demo.service'),
        f(f'{VENDOR}/s.service', '[Service]\nExecStart=/s\n'),
        ln(f'{VENDOR}/sysinit.target.wants/s.service', '../s.service'),
        f(f'{VENDOR}/v.service', SVC),
        ln(f'{ETC}/multi-user.target.wants/v.service', '/opt/other.service'),
    ]
    r, u = run(obs)
    assert u['demo.service']['state'] == 'enabled'
    assert u['demo.service']['enabled_by'][0]['owner'] == 'multi-user.target'
    assert u['s.service']['state'] == 'static' and u['s.service']['static_dependencies']
    assert u['v.service']['state'] == 'disabled'
    assert any(g['code'] == 'foreign_link_target' for g in r['gaps']) and not r['complete']


def test_dangling_enablement_is_reported():
    r, u = run([ln(f'{ETC}/multi-user.target.wants/gone.service', f'{VENDOR}/gone.service')])
    assert u['gone.service']['state'] == 'not_found'
    assert {'dangling_enablement', 'unresolved_link'} & {g['code'] for g in r['gaps']}


def test_alias_and_linked_unit():
    obs = [
        f(f'{VENDOR}/real.service', SVC),
        ln(f'{ETC}/alias.service', f'{VENDOR}/real.service'),
        ln(f'{ETC}/ext.service', '/opt/app/ext.service'),
        f('/opt/app/ext.service', '[Service]\nExecStart=/opt/app/run\n'),
    ]
    r, u = run(obs)
    assert u['alias.service']['alias_of'] == 'real.service' and u['alias.service']['state'] == 'enabled'
    assert u['ext.service']['origin'] == 'linked' and u['ext.service']['classification'] == 'custom'
    assert u['ext.service']['exec']['ExecStart'] == ['/opt/app/run']
    assert r['complete']


def test_unreferenced_external_file_is_a_gap():
    r, _ = run([f('/opt/stray.service', SVC)])
    assert [g['code'] for g in r['gaps']] == ['outside_search_path']


def test_timer_relationships_and_missing_target():
    obs = [
        f(f'{VENDOR}/backup.timer', '[Timer]\nOnCalendar=daily\nOnCalendar=\nOnCalendar=*-*-* 03:00\n'),
        f(f'{VENDOR}/backup.service', '[Service]\nExecStart=/usr/bin/backup\n'),
        f(f'{ETC}/x.timer', '[Timer]\nOnBootSec=5min\nUnit=payload.service\n'),
    ]
    r, u = run(obs)
    t = {x['trigger']: x for x in r['triggers']}
    assert t['backup.timer']['unit'] == 'backup.service' and t['backup.timer']['unit_present']
    assert t['backup.timer']['schedule'] == {'OnCalendar': ['*-*-* 03:00']}
    assert t['x.timer']['explicit'] and not t['x.timer']['unit_present']
    assert t['x.timer']['unit_state'] == 'missing'
    assert any(g['code'] == 'trigger_target_missing' for g in r['gaps'])
    assert u['backup.timer']['triggers_unit'] == 'backup.service'


def test_generated_units_classified():
    _, u = run([f('/run/systemd/generator/-.mount', '[Mount]\nWhat=/dev/sda1\n')])
    assert u['-.mount']['origin'] == 'generated' and u['-.mount']['classification'] == 'generated'


def test_uncollected_roots_and_bad_inputs_are_gaps_never_covered():
    r = su.resolve([f(f'{VENDOR}/a.service', SVC)], collected_roots=[VENDOR])
    assert not r['complete']
    assert {g['path'] for g in r['gaps'] if g['code'] == 'search_path_not_collected'} == set(ALL) - {VENDOR}
    r, u = run([
        {'path': f'{ETC}/../etc/x.service', 'kind': 'file', 'text': SVC},
        {'path': 'relative.service', 'kind': 'file', 'text': SVC},
        {'path': f'{ETC}/bad name.service', 'kind': 'file', 'text': SVC},
        {'path': f'{ETC}/u.service', 'kind': 'unreadable'},
        {'path': f'{ETC}/big.service', 'kind': 'file', 'text': SVC, 'truncated': True},
        {'path': f'{ETC}/weird.service', 'kind': 'fifo'},
        'nope',
    ])
    codes = {g['code'] for g in r['gaps']}
    assert {'invalid_path', 'invalid_unit_name', 'unreadable', 'oversized',
            'unsupported_entry_kind', 'invalid_observation'} <= codes
    assert u['big.service']['state'] == 'unknown' and u['big.service']['incomplete']
    assert u['big.service']['exec'] == {}
    assert su.resolve('x')['gaps'][0]['code'] == 'invalid_observations'


def test_malformed_and_overlong_values_mark_unit_unknown():
    long = 'A' * (su.MAX_VALUE + 1)
    r, u = run([f(f'{ETC}/m.service', f'Orphan=1\n[Service]\nExecStart=/ok\nUser={long}\n')])
    assert u['m.service']['state'] == 'unknown' and u['m.service']['account']['user'] is None
    g = [g for g in r['gaps'] if g['code'] == 'malformed_configuration'][0]
    assert 'malformed_line' in g['detail'] and 'overlong_value' in g['detail']


def test_observation_cap_and_line_continuation():
    obs = [f(f'{ETC}/c.service', '[Service]\nExecStart=/bin/sh \\\n  -c true\n')]
    _, u = run(obs)
    assert u['c.service']['exec']['ExecStart'] == ['/bin/sh -c true']
    r = su.resolve([f(f'{ETC}/x{i}.service', SVC) for i in range(su.MAX_OBSERVATIONS + 1)], ALL)
    assert any(g['code'] == 'observation_cap' for g in r['gaps']) and len(r['units']) == su.MAX_OBSERVATIONS


def test_digest_is_deterministic_and_order_independent():
    obs = [f(f'{VENDOR}/demo.service', SVC), ln(f'{ETC}/multi-user.target.wants/demo.service', f'{VENDOR}/demo.service')]
    a = su.resolve(obs, ALL)
    b = su.resolve(list(reversed(obs)), list(reversed(ALL)))
    assert a['digest'] == b['digest'] and len(a['digest']) == 64
    c = su.resolve([f(f'{VENDOR}/demo.service', SVC.replace('--a', '--b'))], ALL)
    assert c['digest'] != a['digest']


def test_parse_name():
    assert su.parse_name('foo@bar.service')['instance'] == 'bar'
    assert su.parse_name('foo@.timer')['template'] is True
    assert su.parse_name('foo.conf') is None and su.parse_name('x' * 300 + '.service') is None
    assert su.parse_name(None) is None


def test_privileged_exec_prefix_is_flagged():
    _, u = run([f(f'{ETC}/p.service', '[Service]\nUser=nobody\nExecStartPre=+/bin/setup\nExecStart=/bin/run\n'),
                f(f'{ETC}/q.service', '[Service]\nUser=nobody\nExecStart=-/bin/run\n')])
    assert u['p.service']['privileged_exec'] is True
    assert u['q.service']['privileged_exec'] is False
