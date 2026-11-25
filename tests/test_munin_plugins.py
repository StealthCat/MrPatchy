"""Tests for the pure munin-node plugin contract (#1498).

Expected outcomes follow munin 2.0.75 Munin::Node::{Config,Service,OS,Server},
Munin::Common::Config and sbin/munin-node with Debian's build defaults.
"""
from app import munin_plugins as mp

ARGV = ['--foreground']  # munin-node.service: ExecStart=/usr/sbin/munin-node --foreground
# The relevant lines of Debian's shipped munin-node.conf.
NODE_CONF = r"""# Example config-file for munin-node
log_level 4
log_file /var/log/munin/munin-node.log
pid_file /var/run/munin/munin-node.pid
background 1
setsid 1
user root
group root
# Regexps for files to ignore
ignore_file [\#~]$
ignore_file DEADJOE$
ignore_file \.bak$
ignore_file %$
ignore_file \.dpkg-(tmp|new|old|dist)$
ignore_file \.rpm(save|new)$
ignore_file \.pod$
host *
allow ^127\.0\.0\.1$
port 4949
"""
# Excerpt of Debian's /etc/munin/plugin-conf.d/munin-node.
DEBIAN_CONF = """[diskstats]
user munin

[iostat_ios]
user munin

[cps*]
user root

[if_*]
user root

[smart_*]
user root

[postfix*]
group adm
env.logfile mail.log
"""
EXE = {'regular': True, 'executable': True}


def run(node=NODE_CONF, conf=None, plugins=None, argv=ARGV, **kw):
    conf = {'munin-node': DEBIAN_CONF} if conf is None else conf
    plugins = {'cpu': EXE, 'if_eth0': EXE, 'diskstats': EXE} if plugins is None else plugins
    return mp.assess(node, conf, plugins, argv, **kw)


def plugin(result, name):
    return next(p for p in result['plugins'] if p['name'] == name)


def test_debian_defaults_run_wildcard_root_and_default_nobody():
    r = run()
    assert r['complete'], r['gaps']
    assert r['daemon'] == {'user': 'root', 'root': True, 'paranoia': False}
    cpu = plugin(r, 'cpu')
    assert cpu['status'] == 'runs' and cpu['user'] == 'nobody' and cpu['account_source'] == 'build_default'
    assert cpu['groups'] == [{'name': 'munin', 'optional': False}]
    assert cpu['fetch'] == {'argv': ['/etc/munin/plugins/cpu'], 'via_shell': False, 'path_lookup': False}
    assert cpu['config']['argv'] == ['/etc/munin/plugins/cpu', 'config']
    assert cpu['environment'] == [{'name': 'PATH', 'value': mp.DEFAULT_PATH, 'source': 'munin-node'}]
    eth = plugin(r, 'if_eth0')
    assert eth['user'] == 'root' and eth['root'] is True and eth['account_source'] == '[if_*] munin-node:11'
    assert plugin(r, 'diskstats')['user'] == 'munin'
    # nobody/munin are unresolved without an observed passwd map, which is a non-blocking note.
    assert {'code': 'account_not_observed', 'plugin': 'cpu'} in r['gaps']
    assert r['origin'] == 'not_assessed' and r['verdict'] is None


def test_passwd_map_resolves_accounts_and_missing_user_fails_before_exec():
    conf = {'munin-node': DEBIAN_CONF, 'zz-local': '[cpu]\nuser ghost\n'}
    r = run(conf=conf, passwd={'root': 0, 'nobody': 65534, 'munin': 110})
    assert r['complete'] and not [g for g in r['gaps'] if g['code'] == 'account_not_observed']
    assert plugin(r, 'diskstats')['root'] is False
    cpu = plugin(r, 'cpu')
    assert cpu['status'] == 'fails_before_exec' and cpu['reason'] == 'user_missing'


def test_wildcards_apply_most_specific_first_and_never_override_exact_sections():
    conf = {
        '10-a': '[if_*]\nuser root\nenv.PATH /opt/a\n[if_err_*]\nuser munin\n[*]\nenv.LD_PRELOAD /lib/x.so\n',
        '20-b': '[if_eth0]\nenv.PATH /opt/exact\n',
    }
    plugins = {'if_eth0': EXE, 'if_err_eth0': EXE, 'load': EXE}
    r = run(conf=conf, plugins=plugins)
    eth = plugin(r, 'if_eth0')
    assert eth['user'] == 'root'
    env = {e['name']: e for e in eth['environment']}
    assert env['PATH']['value'] == '/opt/exact' and 'wildcard' not in env['PATH']
    assert env['LD_PRELOAD'] == {'name': 'LD_PRELOAD', 'source': '10-a:7', 'wildcard': '*', 'value': '/lib/x.so'}
    # if_err_* sorts after if_* so it is applied first (reverse sort) and wins.
    assert plugin(r, 'if_err_eth0')['user'] == 'munin'
    assert plugin(r, 'load')['user'] == 'nobody'


def test_suffix_wildcard_and_later_file_overrides_earlier_key():
    conf = {'a': '[*_root]\nuser root\n[cpu]\nuser munin\n', 'b': '[cpu]\nuser root\n'}
    r = run(conf=conf, plugins={'disk_root': EXE, 'cpu': EXE, 'root_disk': EXE})
    assert plugin(r, 'disk_root')['user'] == 'root'
    assert plugin(r, 'root_disk')['user'] == 'nobody'
    assert plugin(r, 'cpu')['user'] == 'root' and plugin(r, 'cpu')['account_source'] == 'b:2'


def test_parse_error_drops_rest_of_file_but_keeps_earlier_lines():
    conf = {'a': '[cpu]\nuser root\nbogus value\n[load]\nuser root\n',
            'b': 'user root\n[x]\nuser root\n',
            'c': '[load]\nenv FOO=bar\nuser munin\n'}
    r = run(conf=conf, plugins={'cpu': EXE, 'load': EXE})
    assert plugin(r, 'cpu')['user'] == 'root'
    assert plugin(r, 'load')['user'] == 'nobody'
    files = {f['name']: f for f in r['plugin_conf_files']}
    assert files['a'] == {'name': 'a', 'status': 'aborted', 'line': 3, 'reason': 'unknown_key'}
    assert files['b']['reason'] == 'clutter_before_section'
    assert files['c']['reason'] == 'deprecated_env_format'
    assert r['complete']


def test_zero_line_and_section_named_zero_follow_perl_truthiness():
    conf = {'a': '[cpu]\n0\nuser root\n[0]\nuser root\n'}
    r = run(conf=conf, plugins={'cpu': EXE})
    assert plugin(r, 'cpu')['user'] == 'root'
    assert r['plugin_conf_files'][0] == {'name': 'a', 'status': 'aborted', 'line': 5,
                                         'reason': 'clutter_before_section'}


def test_comments_escapes_groups_and_optional_groups():
    conf = {'a': '[cpu]  # trailing\ngroup adm, (disk) wheel\nenv.password s3cr\\#et\n'}
    r = run(conf=conf, plugins={'cpu': EXE})
    cpu = plugin(r, 'cpu')
    assert cpu['groups'] == [{'name': 'adm', 'optional': False}, {'name': 'disk', 'optional': True},
                             {'name': 'wheel', 'optional': False}]
    env = {e['name']: e for e in cpu['environment']}
    assert env['password'] == {'name': 'password', 'source': 'a:3', 'value_withheld': True}
    assert 's3cr' not in repr(r)


def test_command_expansion_path_lookup_and_perl_single_word_shell():
    conf = {'a': '[cpu]\ncommand sudo -u root %c\n[load]\ncommand /usr/local/bin/x;id\n'
                 '[df]\ncommand %c\n[uptime]\ncommand FOO=1\n'}
    r = run(conf=conf, plugins={'cpu': EXE, 'load': EXE, 'df': EXE, 'uptime': EXE})
    cpu = plugin(r, 'cpu')
    assert cpu['fetch'] == {'argv': ['sudo', '-u', 'root', '/etc/munin/plugins/cpu'],
                            'via_shell': False, 'path_lookup': True}
    assert cpu['config']['argv'][-1] == 'config' and cpu['command_source'] == 'a:2'
    load = plugin(r, 'load')
    # A one-word command drops the argument and Perl sends it through /bin/sh.
    assert load['fetch'] == load['config'] == {'argv': ['/bin/sh', '-c', '/usr/local/bin/x;id'],
                                               'via_shell': True, 'path_lookup': False}
    assert plugin(r, 'df')['fetch']['via_shell'] is False
    assert plugin(r, 'uptime')['fetch']['via_shell'] is True


def test_listing_filters_and_debian_ignore_regexes():
    plugins = {'cpu': EXE, 'cpu~': EXE, 'cpu.bak': EXE, 'cpu.dpkg-old': EXE, '.hidden': EXE, 'x.conf': EXE,
               'we ird': EXE, 'noexec': {'regular': True, 'executable': False},
               'dir': {'regular': False, 'executable': True}, 'a@b:c.d-e': EXE}
    r = run(conf={}, plugins=plugins)
    status = {p['name']: p['status'] for p in r['plugins']}
    # The weird-character rule runs before ignore_file, so cpu~ never reaches [\#~]$.
    assert status == {'cpu': 'runs', 'cpu~': 'invalid_name', 'cpu.bak': 'ignored', 'cpu.dpkg-old': 'ignored', '.hidden': 'hidden',
                      'x.conf': 'config_file', 'we ird': 'invalid_name', 'noexec': 'not_executable_file',
                      'dir': 'not_executable_file', 'a@b:c.d-e': 'runs'}


def test_plugin_conf_files_filtered_like_munin():
    conf = {'local.bak': '[cpu]\nuser root\n', '.x': '[cpu]\nuser root\n', 'a@b': '[cpu]\nuser root\n'}
    r = run(conf=conf, plugins={'cpu': EXE})
    assert plugin(r, 'cpu')['user'] == 'nobody'
    assert {f['name']: f['status'] for f in r['plugin_conf_files']} == {
        '.x': 'ignored', 'a@b': 'invalid_name', 'local.bak': 'ignored'}


def test_default_plugin_user_and_group_from_node_conf():
    node = NODE_CONF + 'default_plugin_user munin\ndefault_client_group adm\n'
    r = run(node=node, conf={}, plugins={'cpu': EXE})
    cpu = plugin(r, 'cpu')
    assert cpu['user'] == 'munin' and cpu['account_source'] == 'default_plugin_user'
    assert cpu['groups'] == [{'name': 'adm', 'optional': False}]


def test_non_root_daemon_runs_every_plugin_as_itself():
    node = NODE_CONF.replace('user root', 'user munin')
    r = run(node=node, passwd={'munin': 110, 'root': 0})
    eth = plugin(r, 'if_eth0')
    assert eth['user'] == 'munin' and eth['root'] is False and eth['configured_user'] == 'root'
    assert eth['account_source'] == 'daemon'


def test_node_setting_name_collisions_follow_perl_failures():
    conf = {'a': '[port]\nuser root\n[cpu]\nuser root\n'}
    r = run(conf=conf, plugins={'port': EXE, 'cpu': EXE})
    assert r['plugin_conf_files'][0]['reason'] == 'section_is_node_setting'
    assert plugin(r, 'port') == {'name': 'port', 'status': 'fails_before_exec',
                                 'reason': 'service_is_node_setting'}
    assert plugin(r, 'cpu')['user'] == 'nobody'


def test_unmodeled_regexes_fail_closed():
    r = run(node=NODE_CONF + 'ignore_file (?i)foo\n')
    assert not r['complete'] and {'code': 'regex_unmodeled', 'ignore_file': '(?i)foo'} in r['gaps']
    assert all(p['status'] == 'unresolved' for p in r['plugins'])
    r = run(conf={'a': '[(?i)IF_*]\nuser root\n'})
    assert not r['complete'] and r['gaps'][0]['code'] == 'regex_unmodeled'


def test_reported_env_values_and_user_path_override():
    conf = {'a': '[cpu]\nenv.PATH /tmp/evil:/usr/bin\nenv.MUNIN_LIBDIR /tmp/lib\nenv.secret x y z\n'}
    cpu = plugin(run(conf=conf, plugins={'cpu': EXE}), 'cpu')
    env = {e['name']: e for e in cpu['environment']}
    assert env['PATH']['value'] == '/tmp/evil:/usr/bin' and env['MUNIN_LIBDIR']['value'] == '/tmp/lib'
    assert env['secret']['value_withheld'] and 'x y z' not in repr(cpu)


def test_argv_handling():
    assert run(argv=['--foreground', '--nodebug', 'extra'])['complete']
    assert run(argv=['--config', '/etc/munin/munin-node.conf'])['complete']
    assert run(argv=['--config=etc/munin/munin-node.conf'])['complete']
    assert {'code': 'config_path_mismatch'} in run(argv=['--config', '/tmp/x.conf'])['gaps']
    assert run(argv=['--help'])['gaps'] == [{'code': 'argv_exits', 'reason': 'help'}]
    assert run(argv=['--config'])['gaps'][0]['reason'] == 'missing_argument'
    assert run(argv=['--debug=1'])['gaps'][0]['code'] == 'argv_exits'
    for word in ('-config', '--conf', '--CONFIG'):
        assert run(argv=[word, 'x'])['gaps'][0]['code'] == 'argv_unmodeled'
    assert not run(argv=None)['complete'] and not run(argv='--foreground')['complete']


def test_paranoia_requires_permission_evidence():
    r = run(argv=['--foreground', '--paranoia'])
    assert not r['complete'] and r['gaps'] == [{'code': 'paranoia_not_observed'}]
    safe = {'plugins': True, 'plugin-conf.d/munin-node': False, 'plugins/cpu': True,
            'plugins/if_eth0': False, 'plugins/diskstats': True}
    r = run(argv=['--foreground', '--paranoia'], paranoia_safe=safe)
    assert r['complete'] and r['plugin_conf_files'][0]['status'] == 'unsafe_permissions'
    assert plugin(r, 'if_eth0')['status'] == 'refused_by_paranoia'
    assert plugin(r, 'diskstats')['user'] == 'nobody'
    # The config file's paranoia line overrides the command line.
    assert run(node=NODE_CONF + 'paranoia no\n', argv=['--paranoia'])['complete']
    r = run(node=NODE_CONF + 'paranoia yes\n', paranoia_safe={'plugins': False})
    assert r['gaps'] == [{'code': 'startup_fatal', 'reason': 'plugins_directory_unsafe'}]


def test_fatal_node_conf_and_daemon_account_gaps():
    assert run(node=NODE_CONF + 'nonsense\n')['gaps'][0]['reason'] == 'line_not_well_formed'
    assert run(node=NODE_CONF + 'paranoia maybe\n')['gaps'][0]['reason'] == 'not_a_boolean'
    r = run(node=NODE_CONF.replace('user root\n', ''))
    assert not r['complete'] and r['gaps'][0] == {'code': 'daemon_user_unresolved', 'reason': 'not_configured'}
    r = run(node=NODE_CONF + 'user nobody\n')
    assert r['gaps'][0]['reason'] == 'ambiguous'
    r = run(node=NODE_CONF.replace('user root', 'user munin'))
    assert not r['complete'] and {'code': 'daemon_user_unresolved', 'reason': 'account_not_observed'} in r['gaps']


def test_unobserved_and_invalid_inputs_fail_closed():
    assert not run(node=None)['complete']
    assert run(node=b'user root\0\n')['gaps'][0]['code'] == 'config_nul'
    assert run(node=b'\xff')['gaps'][0]['code'] == 'config_invalid'
    assert run(node='#' * (mp.MAX_TEXT + 1))['gaps'][0]['code'] == 'config_too_large'
    r = mp.assess(NODE_CONF, None, {'cpu': EXE}, ARGV)
    assert not r['complete'] and {'code': 'plugin_conf_not_observed'} in r['gaps']
    r = run(conf={'a': None})
    assert not r['complete'] and r['plugin_conf_files'][0]['status'] == 'unresolved'
    assert not mp.assess(NODE_CONF, {}, None, ARGV)['complete']
    assert not run(plugins={'cpu': {'regular': True}})['complete']
    assert not run(plugins={'a/b': EXE})['complete']
    r = run(plugins={'cpu\n': EXE})
    assert not r['complete'] and {'code': 'name_unmodeled', 'plugin': 'cpu\n'} in r['gaps']


def test_perl_regex_subset():
    for ok in (r'[\#~]$', r'\.dpkg-(tmp|new|old|dist)$', '^if_', '%$', 'a{1,3}b', r'[]x]', r'[^]x]'):
        assert mp._perl_regex(ok) is not None, ok
    for bad in ('(?i)x', r'\Qx', '$foo', '[[:alpha:]]', 'a**', r'\1', '[abc', 'café'):
        assert mp._perl_regex(bad) is None, bad


def test_unpaired_surrogates_are_invalid_input_not_a_crash():
    # Review of b9e9aef: these raised UnicodeEncodeError in the UTF-8 size check.
    r = run(node=NODE_CONF + '# \ud800\n')
    assert not r['complete'] and r['gaps'][0]['code'] == 'config_invalid'
    r = run(conf={'munin-node': DEBIAN_CONF + '# \udfff\n'})
    assert not r['complete']
    assert {'code': 'plugin_conf_invalid', 'file': 'munin-node'} in r['gaps']
    assert r['plugin_conf_files'][0]['status'] == 'unresolved'
    assert run(plugins={'cpu\ud800': EXE})['gaps'][0]['code'] == 'plugins_invalid'
    assert run(conf={'a\ud800': ''})['gaps'][0]['code'] == 'plugin_conf_invalid'


def test_names_longer_than_name_max_are_invalid():
    assert run(plugins={'a' * (mp.MAX_NAME + 1): EXE})['gaps'][0]['code'] == 'plugins_invalid'
    assert run(conf={'a' * (mp.MAX_NAME + 1): ''})['gaps'][0]['code'] == 'plugin_conf_invalid'
    assert run(plugins={'a' * mp.MAX_NAME: EXE})['complete']


def test_perl_regex_subset_is_bounded():
    for ok in ('^if_.*', 'a+b*', 'a{3}b{2}c{1,2}', 'a*?b', '(ab|cd|ef)x', r'\w+_\d+$', 'a{2,}'):
        assert mp._perl_regex(ok) is not None, ok
    for bad in ('(a+)+$', '(a|aa)*', '(ab){2,9}', 'a*b*c*', 'a{1,999}', 'a{,3}', 'a{2',
                '|'.join('abcdefgh'), '^*', '(*a)', '[a]{1,2}{3}'):
        assert mp._perl_regex(bad) is None, bad


def test_worst_case_bounded_regexes_finish_quickly_on_name_max_subjects():
    import time
    # Accepted patterns that maximise backtracking under the bounds.
    worst = ['.*.*x', 'a*a*b', '(a|a)(a|a)(a|a)(a|a)(a|a)(a|a)a*a*b', r'\w+\w+!',
             'a{0,255}a{0,255}b']
    names = ['a' * mp.MAX_NAME, '_' * mp.MAX_NAME]
    start = time.perf_counter()
    for fragment in worst:
        pattern = mp._perl_regex(fragment)
        assert pattern is not None, fragment
        for name in names:
            assert pattern.search(name) is None
    assert time.perf_counter() - start < 5


def test_wildcard_with_grouped_repetition_is_unmodeled():
    r = run(conf={'a': '[(a+)+*]\nuser root\n'})
    assert not r['complete']
    assert {'code': 'regex_unmodeled', 'section': '(a+)+*'} in r['gaps']
