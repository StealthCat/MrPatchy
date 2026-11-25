"""Pure supervisord program contract (#1259)."""
from app import supervisor_programs as sp

MAIN = '/etc/supervisor/supervisord.conf'
BASE = '[supervisord]\nlogfile=/var/log/supervisor/supervisord.log\n'


def run(main, files=None, globs=None, **kw):
    return sp.evaluate(main_path=MAIN, files={MAIN: main, **(files or {})}, globs=globs or {}, **kw)


def test_default_autostart_program_runs_as_supervisord_user():
    r = run(BASE + '[program:web]\ncommand=/usr/bin/web --port 80 ; comment\n')
    assert r['status'] == 'loads' and r['complete'] and r['origin'] == 'not_assessed'
    [p] = r['processes']
    assert p['command'] == '/usr/bin/web --port 80'
    assert p['starts'] == 'at_supervisord_start' and p['user'] is None and p['runs_as'] == 'supervisord user'


def test_include_order_here_expansion_and_on_demand():
    conf_d = '/etc/supervisor/conf.d'
    r = run(BASE + '[include]\nfiles = conf.d/*.conf\n',
            files={conf_d + '/b.conf': '[program:b]\ncommand=%(here)s/b\nautostart=false\nuser=svc\n',
                   conf_d + '/a.conf': '[program:a]\ncommand=/bin/a %(program_name)s\n'},
            globs={conf_d + '/*.conf': [conf_d + '/b.conf', conf_d + '/a.conf']})
    assert r['files_read'] == [MAIN, conf_d + '/a.conf', conf_d + '/b.conf']
    got = {p['program_name']: p for p in r['processes']}
    assert got['a']['command'] == '/bin/a a' and got['b']['command'] == conf_d + '/b'
    assert got['b']['starts'] == 'on_demand' and got['b']['user'] == 'svc' and r['complete']


def test_numprocs_expands_each_process():
    r = run(BASE + '[program:w]\ncommand=/bin/w %(process_num)02d\nnumprocs=2\nprocess_name=%(program_name)s_%(process_num)s\n')
    assert [(p['process_name'], p['command']) for p in r['processes']] == [('w_0', '/bin/w 00'), ('w_1', '/bin/w 01')]


def test_numprocs_without_process_num_stops_supervisord():
    r = run(BASE + '[program:w]\ncommand=/bin/w\nnumprocs=2\n')
    assert r['status'] == 'config_error' and r['processes'] == []


def test_config_errors_mirror_supervisord():
    for text in ('[program:a]\ncommand=/bin/a\n', BASE + '[program:a]\nautostart=yes\n',
                 BASE + '[program:a]\ncommand=/bin/a\nautostart=maybe\n', BASE + '[include]\n',
                 BASE + '[program:a b]\ncommand=/bin/a\n', BASE + '[program:a]\ncommand=/bin/%(nope)s\n',
                 BASE + '[group:g]\nprograms=zz\n', BASE + 'not an ini line\n'):
        assert run(text)['status'] == 'config_error', text


def test_default_section_applies_to_programs():
    r = run(BASE + '[DEFAULT]\nautostart=false\n[program:a]\ncommand=/bin/a\n')
    assert r['processes'][0]['starts'] == 'on_demand'


def test_unobserved_include_glob_and_file_fail_closed():
    r = run(BASE + '[include]\nfiles = conf.d/*.conf\n')
    assert not r['complete'] and r['gaps'][0]['code'] == 'glob_not_observed'
    conf = '/etc/supervisor/conf.d/x.conf'
    r = run(BASE + '[include]\nfiles = conf.d/*.conf\n', files={conf: None}, globs={'/etc/supervisor/conf.d/*.conf': [conf]})
    assert not r['complete'] and r['gaps'][0]['code'] == 'file_not_observed'


def test_unobserved_environment_marks_command_unresolved():
    r = run(BASE + '[program:a]\ncommand=/bin/a %(ENV_HOME)s\n')
    [p] = r['processes']
    assert p['starts'] == 'unresolved' and p['command'] is None
    r = run(BASE + 'environment=HOME="/root"\n[program:a]\ncommand=/bin/a %(ENV_HOME)s\n')
    assert r['processes'][0]['command'] == '/bin/a /root'


def test_include_pattern_needing_host_name_is_blocking():
    r = run(BASE + '[include]\nfiles = %(host_node_name)s/*.conf\n')
    assert not r['complete'] and r['gaps'][0]['code'] == 'include_expansion_unresolved'
    r = run(BASE + '[include]\nfiles = %(host_node_name)s/*.conf\n', node_name='h1',
            globs={'/etc/supervisor/h1/*.conf': []})
    assert r['complete'] and r['status'] == 'no_processes'


def test_eventlistener_events_are_validated():
    ok = run(BASE + '[eventlistener:m]\ncommand=/bin/m\nevents=TICK_60\n')
    assert ok['processes'][0]['kind'] == 'eventlistener'
    assert run(BASE + '[eventlistener:m]\ncommand=/bin/m\nevents=NOPE\n')['status'] == 'config_error'
    assert run(BASE + '[eventlistener:m]\ncommand=/bin/m\n')['status'] == 'config_error'


def test_binary_invalid_and_relative_inputs_fail_closed():
    assert not run(b'\0')['complete']
    assert not run(b'\xff')['complete']
    assert not sp.evaluate(main_path='rel.conf', files={}, globs={})['complete']
    assert run(None)['status'] == 'unresolved'
