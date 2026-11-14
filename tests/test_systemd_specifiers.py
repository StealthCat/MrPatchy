"""Bounded systemd specifier expansion in the pure unit contract (#702)."""
from app import systemd_units as su

ETC = '/etc/systemd/system'
VENDOR = '/usr/lib/systemd/system'
ALL = [root for root, _ in su.SEARCH_PATHS]


def f(path, text):
    return {'path': path, 'kind': 'file', 'text': text}


def ln(path, target):
    return {'path': path, 'kind': 'symlink', 'target': target}


def run(obs):
    r = su.resolve(obs, collected_roots=ALL)
    return r, {u['name']: u for u in r['units']}


def test_name_specifiers_follow_systemd_unit_5():
    s = su.name_specifiers('dev-disk-by\\x2dlabel-data.mount')
    assert s['n'] == 'dev-disk-by\\x2dlabel-data.mount' and s['N'] == 'dev-disk-by\\x2dlabel-data'
    assert s['p'] == 'dev-disk-by\\x2dlabel-data' and s['P'] == 'dev/disk/by-label/data'
    assert s['i'] == '' and s['I'] == '' and s['j'] == 'data' and s['J'] == 'data'
    assert s['f'] == '/dev/disk/by-label/data'
    inst = su.name_specifiers('backup-job@srv-www\\x2d1.service')
    assert inst['p'] == 'backup-job' and inst['P'] == 'backup/job'
    assert inst['i'] == 'srv-www\\x2d1' and inst['I'] == 'srv/www-1'
    assert inst['j'] == 'job' and inst['f'] == '/srv/www-1'
    assert su.name_specifiers('getty@-.service')['f'] == '/'
    assert su.name_specifiers('getty@.service') is None
    assert su.name_specifiers('bad name') is None
    assert 'I' not in su.name_specifiers('x@a\\x00b.service')
    assert 'P' not in su.name_specifiers('bad\\xZZ.service')


def test_expand_specifiers_never_returns_partial_text():
    table = {'i': 'tty1', 'n': 'getty@tty1.service'}
    assert su.expand_specifiers('/sbin/agetty %i 100%%', table) == ('/sbin/agetty tty1 100%', [])
    assert su.expand_specifiers('/bin/x %i %H', table) == ('/bin/x %i %H', ['H'])
    assert su.expand_specifiers('/bin/x %', table) == ('/bin/x %', ['%'])
    assert su.expand_specifiers('plain', table) == ('plain', [])


def test_instance_exec_account_and_paths_are_expanded_from_template():
    tmpl = ('[Service]\nUser=svc-%i\nGroup=%p\nWorkingDirectory=%f\nEnvironmentFile=-%E/app/%i.env\n'
            'ExecStartPre=+/usr/bin/prep %n\nExecStart=/usr/bin/app --name %I --home %h --run %t/%N\n')
    r, u = run([f(f'{VENDOR}/app@.service', tmpl),
                ln(f'{ETC}/multi-user.target.wants/app@blue.service', f'{VENDOR}/app@.service')])
    a = u['app@blue.service']
    assert a['specifiers'] == 'expanded'
    svc = a['expanded']['Service']
    assert svc['ExecStart'] == ['/usr/bin/app --name blue --home /root --run /run/app@blue']
    assert svc['ExecStartPre'] == ['+/usr/bin/prep app@blue.service']
    assert svc['User'] == 'svc-blue' and svc['Group'] == 'app' and svc['WorkingDirectory'] == '/blue'
    assert svc['EnvironmentFile'] == ['-/etc/app/blue.env']
    # Raw configuration and the existing record fields stay unexpanded.
    assert a['exec']['ExecStart'] == ['/usr/bin/app --name %I --home %h --run %t/%N']
    assert a['account']['user'] == 'svc-%i'
    tpl = u['app@.service']
    assert tpl['expanded'] is None and tpl['specifiers'] == 'not_applicable'
    assert r['complete'] and r['contract_version'] == 2


def test_host_and_environment_specifiers_are_gaps_not_guesses():
    r, u = run([f(f'{ETC}/probe.service',
                  '[Service]\nExecStart=/usr/bin/probe --host %H --tmp %T\nExecStop=/bin/true %n\n')])
    p = u['probe.service']
    assert p['specifiers'] == 'partial' and p['incomplete']
    assert p['expanded']['Service']['ExecStart'] == ['/usr/bin/probe --host %H --tmp %T']
    assert p['expanded']['Service']['ExecStop'] == ['/bin/true probe.service']
    assert {'code': 'unexpanded_specifier', 'path': f'{ETC}/probe.service', 'detail': '%H,%T'} in r['gaps']
    assert not r['complete']


def test_units_without_specifiers_and_masked_units():
    _, u = run([f(f'{VENDOR}/plain.service', '[Service]\nExecStart=/usr/bin/plain\n'),
                ln(f'{ETC}/gone.service', '/dev/null')])
    assert u['plain.service']['specifiers'] == 'none'
    assert u['plain.service']['expanded'] == {'Service': {'ExecStart': ['/usr/bin/plain']}}
    assert u['gone.service']['specifiers'] == 'none' and u['gone.service']['expanded'] == {}


def test_dropin_reset_is_applied_before_expansion():
    _, u = run([f(f'{VENDOR}/web.service', '[Service]\nExecStart=/usr/bin/web %N\n'),
                f(f'{ETC}/web.service.d/override.conf', '[Service]\nExecStart=\nExecStart=/opt/web %p\n')])
    assert u['web.service']['expanded']['Service']['ExecStart'] == ['/opt/web web']


def test_user_manager_specifiers_use_account_home_and_runtime_dir():
    home, rt = '/home/alice', '/run/user/1000'
    table, _ = su.user_search_paths(home, rt)
    conf = f'{home}/.config/systemd/user'
    r = su.resolve_user([f(f'{conf}/sync.service',
                           '[Service]\nExecStart=/usr/bin/sync %u %h %t %E %C\nExecStop=/bin/kill %U %S\n')],
                        home, rt, 'alice', collected_roots=[root for root, _ in table])
    s = {x['name']: x for x in r['units']}['sync.service']
    svc = s['expanded']['Service']
    assert svc['ExecStart'] == ['/usr/bin/sync alice /home/alice /run/user/1000 /home/alice/.config /home/alice/.cache']
    assert svc['ExecStop'] == ['/bin/kill %U %S'] and s['specifiers'] == 'partial'
    assert {'code': 'unexpanded_specifier', 'path': f'{conf}/sync.service', 'detail': '%S,%U'} in r['gaps']


def test_invalid_user_home_leaves_home_specifiers_unexpanded():
    rt = '/run/user/1000'
    table, _ = su.user_search_paths('relative', rt)
    r = su.resolve_user([f(f'{rt}/systemd/user/t.service', '[Service]\nExecStart=/bin/t %h %t\n')],
                        'relative', rt, 'alice', collected_roots=[root for root, _ in table])
    t = {x['name']: x for x in r['units']}['t.service']
    assert t['expanded']['Service']['ExecStart'] == ['/bin/t %h %t'] and t['specifiers'] == 'partial'
