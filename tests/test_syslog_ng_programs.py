"""Tests for the pure syslog-ng command contract (#1570).

Expected outcomes were observed with the real syslog-ng 4.3.1 (Ubuntu 24.04
``syslog-ng-core 4.3.1-2build5``) running as root. The live differential at
the end reruns the cases when ``MRPATCHY_SYSLOG_NG`` names a syslog-ng binary
and the tests run as root.
"""
import os
import shutil
import subprocess
import tempfile
import time

import pytest

from app import syslog_ng_programs as sp

CONF = sp.DEFAULT_CONFIG
CONF_D = '/etc/syslog-ng/conf.d'

# Abridged Ubuntu 24.04 default configuration.
UBUNTU = """@version: 3.38
@include "scl.conf"
options { chain_hostnames(off); flush_lines(0); use_dns(no); use_fqdn(no);
          dns_cache(no); owner("root"); group("adm"); perm(0640);
          stats(freq(0)); bad_hostname("^gconfd$");
};
source s_src { system(); internal(); };
destination d_auth { file("/var/log/auth.log"); };
destination d_console_all { getvirtconsole(); };
filter f_auth { facility(auth, authpriv); };
log { source(s_src); filter(f_auth); destination(d_auth); };
#log { source(s_src); filter(f_cnews); destination(d_console_all); };
@include "/etc/syslog-ng/conf.d/*.conf"
"""
UBUNTU_CONSOLE = 'log { source(s_src); destination(d_console_all); };\n'

SCL = """@module confgen context(destination) name(getvirtconsole) exec("`scl-root`/getvirtconsole/tty10.sh")
@module appmodel
@include 'scl/*/*.conf'
"""


def run(main, extra=None, listings=None, **kwargs):
    files = {CONF: main, **(extra or {})}
    if listings is None:
        listings = {CONF_D: [p.rsplit('/', 1)[1] for p in (extra or {}) if p.startswith(CONF_D + '/')]}
    return sp.resolve(files, listings, **kwargs)


def codes(result):
    return [gap['code'] for gap in result['gaps']]


def running(result):
    return [(c['kind'], c['command']) for c in result['commands'] if c['status'] == 'runs']


def head(body):
    return '@version: 4.2\nsource s { internal(); };\n' + body


@pytest.mark.parametrize('body, expected', [
    ('a\\tb', 'a\tb'), ('\\x41', 'A'), ('\\\\q', '\\q'), ('\\"z\\"', '"z"'), ('\\n', '\n'), ('\\q', 'q'),
    ('\\x4', 'x4'),
])
def test_double_quoted_escapes(body, expected):
    assert sp.decode_double(body) == expected


@pytest.mark.parametrize('console', [False, True])
def test_ubuntu_default_with_scl(console):
    # Observed natively with the packaged configuration: syslog-ng ran
    # "sh -c -- /usr/share/syslog-ng/include/scl/getvirtconsole/tty10.sh" as root because
    # d_console_all is used by a log path. `scl-root` is a built-in variable, so the contract
    # reports the command as unresolved instead of guessing the path.
    scl_dir = '/usr/share/syslog-ng/include/scl'
    result = sp.resolve(
        {CONF: UBUNTU + (UBUNTU_CONSOLE if console else ''), '/usr/share/syslog-ng/include/scl.conf': SCL,
         f'{scl_dir}/getvirtconsole/plugin.conf':
             '@module confgen context(destination) name(getvirtconsole) exec("`scl-root`/getvirtconsole/tty10.sh")\n'},
        {CONF_D: [], '/etc/syslog-ng': ['conf.d', 'syslog-ng.conf'], scl_dir: ['getvirtconsole'],
         f'{scl_dir}/getvirtconsole': ['plugin.conf']})
    assert result['starts'] and result['running'] == []
    (gen,) = result['commands']
    assert (gen['kind'], gen['driver'], gen['object']) == ('confgen', 'getvirtconsole', 'd_console_all')
    assert gen['argv'] == ['sh', '-c', '--', '`scl-root`/getvirtconsole/tty10.sh']
    if console:
        assert gen['status'] == 'unresolved' and gen['unresolved_backticks'] == ['scl-root']
        assert codes(result) == ['confgen_output', 'backtick_unresolved'] and not result['complete']
    else:
        assert gen['status'] == 'not_referenced' and result['complete'] and result['gaps'] == []
    assert result['origin'] == 'not_assessed' and result['authorizes_response'] is False
    assert [f['path'] for f in result['files']] == [
        CONF, '/usr/share/syslog-ng/include/scl.conf', f'{scl_dir}/getvirtconsole/plugin.conf']


def test_program_destination_and_source_run_through_bin_sh_only_when_referenced():
    # Observed: d1, d2 and sp ran under "/bin/sh -c <string>" as uid 0; dunused never ran.
    result = run(head(
        'destination d1 { program("PROBE_TAG=d1 /tmp/sng/probe.sh a \'b c\' \\"d e\\" $HOME"); };\n'
        "destination d2 { program('PROBE_TAG=d2 /tmp/sng/probe.sh x\\ty'); };\n"
        'destination dunused { program("PROBE_TAG=unused /tmp/sng/probe.sh"); };\n'
        'source sp { program("PROBE_TAG=src /tmp/sng/probe.sh srcarg"); };\n'
        'log { source(s); destination(d1); destination(d2); };\n'
        'log { source(sp); destination(d1); };\n'))
    assert result['complete'] and result['starts']
    by_object = {c['object']: c for c in result['commands']}
    assert by_object['d1']['argv'] == ['/bin/sh', '-c', 'PROBE_TAG=d1 /tmp/sng/probe.sh a \'b c\' "d e" $HOME']
    assert by_object['d2']['command'] == 'PROBE_TAG=d2 /tmp/sng/probe.sh x\\ty'
    assert by_object['sp']['kind'] == 'program_source' and by_object['sp']['status'] == 'runs'
    assert by_object['dunused']['status'] == 'not_referenced'
    assert by_object['d1']['runs_as']['user'] == 'root'
    assert by_object['d1']['line'] == 3 and by_object['d1']['path'] == CONF
    assert len(result['running']) == 3


def test_escapes_backticks_and_inline_destinations():
    # Observed: "A<TAB>B A \\q "z"", the @define expansion, and the inline destination.
    result = run(head(
        '@define probe "/tmp/sng/probe.sh"\n'
        'destination e1 { program("PROBE_TAG=e1 /tmp/sng/probe.sh A\\tB \\x41 \\\\q \\"z\\" "); };\n'
        'destination e2 { program("PROBE_TAG=e2 `probe` bt"); };\n'
        'log { source(s); destination(e1); destination(e2);\n'
        '  destination { program("PROBE_TAG=inline /tmp/sng/probe.sh"); };\n};\n'
        'log { source(s); destination(e1); };\n'))
    assert result['complete']
    assert running(result) == [
        ('program_destination', 'PROBE_TAG=e1 /tmp/sng/probe.sh A\tB A \\q "z" '),
        ('program_destination', 'PROBE_TAG=e2 /tmp/sng/probe.sh bt'),
        ('program_destination', 'PROBE_TAG=inline /tmp/sng/probe.sh'),
    ]
    assert result['commands'][2]['object'] is None


def test_adjacent_strings_reject_the_configuration():
    # Observed: "syntax error, unexpected LL_STRING"; syslog-ng exited 1.
    result = run(head('destination e1 { program("a" "b"); };\nlog { source(s); destination(e1); };\n'))
    assert not result['starts'] and result['fatal'][0]['code'] == 'syntax'
    assert result['commands'][0]['status'] == 'rejected' and result['running'] == []


def test_glob_and_directory_includes_late_define_and_dedup():
    # Observed: dirz, dup (once), ia (with `late` empty) and ib ran; hidden, txt and y~ did not.
    inc = {
        '/tmp/sng/inc.d/b.conf': 'destination ib { program("PROBE_TAG=ib /tmp/sng/probe.sh"); };\n'
                                 'log { source(s); destination(ib); };\n',
        '/tmp/sng/inc.d/a.conf': 'destination ia { program("PROBE_TAG=ia /tmp/sng/probe.sh `late`"); };\n'
                                 'log { source(s); destination(ia); };\n',
        '/tmp/sng/incdir/z': 'destination iz { program("PROBE_TAG=dirz /tmp/sng/probe.sh"); };\n'
                             'log { source(s); destination(iz); };\n',
    }
    listings = {'/tmp/sng/inc.d': ['b.conf', 'a.conf', '.hidden.conf', 'c.txt'], '/tmp/sng/incdir': ['z', 'y~'],
                '/tmp/sng': ['inc.d', 'incdir']}
    result = sp.resolve({CONF: head(
        '@include "/tmp/sng/inc.d/*.conf"\n@include "/tmp/sng/incdir"\n@include "/tmp/sng/nomatch/*.conf"\n'
        '@define late "LATE"\n'
        'destination d { program("PROBE_TAG=dup /tmp/sng/probe.sh"); };\n'
        'log { source(s); destination(d); };\nlog { source(s); destination(d); };\n'), **inc}, listings)
    assert [c['object'] for c in result['commands']] == ['ia', 'ib', 'iz', 'd']
    ia = result['commands'][0]
    # syslog-ng substituted an empty string; the contract cannot tell an environment variable from nothing.
    assert ia['status'] == 'unresolved' and ia['unresolved_backticks'] == ['late']
    assert [c['status'] for c in result['commands'][1:]] == ['runs', 'runs', 'runs']
    assert not result['complete'] and 'backtick_unresolved' in codes(result)
    assert 'listing_not_observed' not in codes(result)


def test_directory_include_takes_only_safe_names_in_sorted_order():
    # Observed order: UPPER, a.bak, a1, b2, x-y_z.1 (".dot", "has space", "semi;x", "#hash" skipped).
    names = ['b2', '.dot', 'has space', 'a.bak', 'UPPER', 'x-y_z.1', 'a1', 'semi;x', '#hash']
    files = {f'/tmp/sng/d2/{n}': f'destination "dd_{n}" {{ program("PROBE_TAG={n} p"); }};\n'
                                  f'log {{ source(s); destination("dd_{n}"); }};\n' for n in names}
    result = sp.resolve({CONF: head('@include "/tmp/sng/d2"\n'), **files}, {'/tmp/sng/d2': names})
    assert result['complete']
    assert [c['object'] for c in result['running']] == ['dd_UPPER', 'dd_a.bak', 'dd_a1', 'dd_b2', 'dd_x-y_z.1']


def test_hook_commands_run_through_sh_dash_dash_for_referenced_drivers_only():
    # Observed: startup, setup at start and teardown, shutdown at stop, all "sh -c -- <string>"; hu never ran.
    result = run(head(
        'destination h { file("/tmp/sng/h.out" hook-commands(setup("S") startup("U") teardown("T") '
        'shutdown("D"))); };\n'
        'destination hu { file("/tmp/sng/h2.out" hook_commands(startup("unused-hook"))); };\n'
        'log { source(s); destination(h); };\n'))
    hooks = [(c['hook'], c['status'], c['argv']) for c in result['commands']]
    assert hooks == [
        ('setup', 'runs', ['sh', '-c', '--', 'S']), ('startup', 'runs', ['sh', '-c', '--', 'U']),
        ('teardown', 'runs', ['sh', '-c', '--', 'T']), ('shutdown', 'runs', ['sh', '-c', '--', 'D']),
        ('startup', 'not_referenced', ['sh', '-c', '--', 'unused-hook']),
    ]
    assert result['complete']


def test_confgen_runs_only_when_used_and_its_output_is_a_gap():
    # Observed: the generator used by source g ran as "sh -c -- <string>"; unused generators did not.
    result = run(head(
        '@module confgen context(source) name(mygen) exec("PROBE_TAG=confgen /tmp/sng/gen.sh")\n'
        '@module confgen context(destination) name(unusedgen) exec("never")\n'
        'source g { mygen(); };\nlog { source(g); };\n'))
    assert [(c['kind'], c['driver'], c['status'], c['argv']) for c in result['commands']] == [
        ('confgen', 'mygen', 'runs', ['sh', '-c', '--', 'PROBE_TAG=confgen /tmp/sng/gen.sh'])]
    assert codes(result) == ['confgen_output'] and not result['complete']


def test_unresolved_reference_and_duplicate_definition_stop_syslog_ng():
    # Observed: "Error resolving reference" and "duplicate destination definition"; nothing ran.
    missing = run(head('destination d { program("a"); };\nlog { source(s); destination(nosuch); };\n'
                       'log { source(s); destination(d); };\n'))
    assert not missing['starts'] and missing['fatal'][0]['code'] == 'unresolved_reference'
    assert missing['commands'][0]['status'] == 'rejected'
    dup = run(head('destination d { program("first"); };\ndestination d { program("second"); };\n'
                   'log { source(s); destination(d); }; # program("comment")\n'))
    assert not dup['starts'] and dup['fatal'][0]['code'] == 'duplicate_definition'
    assert [c['command'] for c in dup['commands']] == ['first', 'second']
    allowed = run(head('@define allow-config-dups 1\ndestination d { program("x"); };\n'
                       'destination d { program("y"); };\nlog { source(s); destination(d); };\n'))
    assert allowed['starts'] and 'allow_config_dups' in codes(allowed) and not allowed['complete']


def test_relative_include_search_order_and_missing_include():
    # Observed: "scl.conf" was looked up in /etc/syslog-ng then /usr/share/syslog-ng/include;
    # a missing "nofile.conf" stopped syslog-ng ("Error including nofile.conf").
    found = sp.resolve({CONF: head('@include "x.conf"\n'),
                        '/usr/share/syslog-ng/include/x.conf': 'destination d { program("p"); };\n'
                                                               'log { source(s); destination(d); };\n'},
                       {'/etc/syslog-ng': ['syslog-ng.conf'], '/usr/share/syslog-ng/include': ['x.conf']})
    assert found['complete'] and found['running'][0]['path'] == '/usr/share/syslog-ng/include/x.conf'
    missing = sp.resolve({CONF: head('@include "nofile.conf"\n')},
                         {'/etc/syslog-ng': ['syslog-ng.conf'], '/usr/share/syslog-ng/include': []})
    assert not missing['starts'] and missing['fatal'][0]['code'] == 'include_not_found'
    unknown = sp.resolve({CONF: head('@include "nofile.conf"\n')}, {})
    assert unknown['starts'] and codes(unknown) == ['file_not_observed'] and not unknown['complete']


def test_fail_closed_inputs():
    assert codes(sp.resolve({}, {})) == ['file_not_observed']
    assert codes(sp.resolve({CONF: b'\xff'}, {})) == ['invalid_utf8']
    assert codes(sp.resolve({CONF: 'a\0b'}, {})) == ['binary']
    assert codes(sp.resolve({CONF: '#' * (sp.MAX_TEXT + 1)}, {})) == ['over_limit']
    assert codes(run('destination d { program("unterminated); };\n')) == ['syntax']
    assert codes(run('destination d { program("x"); \n')) == ['syntax']
    glob = run(head('@include "/etc/syslog-ng/other.d/*.conf"\n'), listings={})
    assert codes(glob) == ['listing_not_observed'] and not glob['complete']
    loop = sp.resolve({CONF: '@include "/etc/syslog-ng/syslog-ng.conf"\n'}, {'/etc/syslog-ng': ['syslog-ng.conf']})
    assert 'include_depth' in codes(loop) and not loop['complete']


def test_block_driver_and_unresolved_backtick_in_running_command():
    blocked = run(head('block destination mine(cmd("")) { program("`cmd`"); };\n'
                       'destination d { mine(cmd("evil")); };\nlog { source(s); destination(d); };\n'))
    assert codes(blocked) == ['block_driver'] and not blocked['complete']
    env = run(head('destination d { program("`HOME`/bin/x"); };\nlog { source(s); destination(d); };\n'))
    assert env['commands'][0]['status'] == 'unresolved' and 'backtick_unresolved' in codes(env)
    unused = run(head('destination d { program("`HOME`/bin/x"); };\n'))
    assert unused['complete'] and unused['commands'][0]['status'] == 'not_referenced'


def test_conf_d_drop_in_is_reported_with_its_location():
    result = run(UBUNTU, {f'{CONF_D}/zz-ship.conf': '\n\ndestination d_ship {\n  program("/usr/local/bin/ship --all"'
                                                     ' inherit-environment(no));\n};\n'
                                                     'log { source(s_src); destination(d_ship); };\n',
                          '/usr/share/syslog-ng/include/scl.conf': '# empty\n'},
                 listings={CONF_D: ['zz-ship.conf'], '/etc/syslog-ng': ['conf.d', 'syslog-ng.conf']})
    assert result['complete']
    (cmd,) = result['running']
    assert (cmd['path'], cmd['line'], cmd['command']) == (f'{CONF_D}/zz-ship.conf', 4, '/usr/local/bin/ship --all')


# --- optional live differential ---------------------------------------------------------------------------

LIVE = os.environ.get('MRPATCHY_SYSLOG_NG')
PROBE = """#!/bin/sh
printf '%s\\n' "$(tr '\\0' '|' </proc/$PPID/cmdline)" >> {out}
"""


@pytest.mark.skipif(not LIVE or os.geteuid() != 0, reason='set MRPATCHY_SYSLOG_NG and run as root')
@pytest.mark.parametrize('body', [
    'destination a { program("{probe} one \'two three\'"); };\ndestination b { program("{probe} unused"); };\n'
    'log { source(s); destination(a); };\n',
    'source p { program("{probe} src"); };\nlog { source(p); destination { program("{probe} inline"); }; };\n',
    'destination h { file("{dir}/h.out" hook-commands(startup("{probe} up") shutdown("{probe} down"))); };\n'
    'log { source(s); destination(h); };\n',
    '@include "{dir}/inc"\n',
])
def test_live_differential(body):
    directory = tempfile.mkdtemp()
    try:
        out = os.path.join(directory, 'out.log')
        probe = os.path.join(directory, 'probe.sh')
        with open(probe, 'w') as handle:
            handle.write(PROBE.format(out=out))
        os.chmod(probe, 0o755)
        inc = os.path.join(directory, 'inc')
        os.mkdir(inc)
        for name in ('b', 'a', '.c'):
            with open(os.path.join(inc, name), 'w') as handle:
                handle.write(f'destination i{name.strip(".")} {{ program("{probe} inc-{name}"); }};\n'
                             f'log {{ source(s); destination(i{name.strip(".")}); }};\n')
        conf = os.path.join(directory, 'test.conf')
        text = head(body.replace('{probe}', probe).replace('{dir}', directory))
        with open(conf, 'w') as handle:
            handle.write(text)
        files = {conf: text}
        for name in os.listdir(inc):
            with open(os.path.join(inc, name)) as handle:
                files[os.path.join(inc, name)] = handle.read()
        expected = sp.resolve(files, {inc: os.listdir(inc), directory: os.listdir(directory)}, config=conf)
        proc = subprocess.Popen([LIVE, '-F', '-f', conf, '-R', os.path.join(directory, 'persist'),
                                 '-c', os.path.join(directory, 'ctl'), '-p', os.path.join(directory, 'pid'),
                                 '--no-caps'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        proc.send_signal(2)
        proc.wait(timeout=10)
        seen = set()
        if os.path.exists(out):
            with open(out) as handle:
                seen = {line.rstrip('\n').rstrip('|') for line in handle}
        assert seen == {'|'.join(c['argv']) for c in expected['running']}
    finally:
        shutil.rmtree(directory, ignore_errors=True)
